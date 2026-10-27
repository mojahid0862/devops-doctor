import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import doctor_common as common


class CommonTests(unittest.TestCase):
    def test_text_secrets_and_urls(self):
        samples = ['TOKEN="synthetic-secret-one"', "password='synthetic-secret-two'", '{"password": "synthetic-secret-three"}', 'Authorization: Bearer synthetic-secret-four', 'https://user:synthetic-secret-five@example.test/repo', 'https://example.test/file?X-Amz-Signature=synthetic-secret-six', 'https://hooks.slack.com/services/synthetic-secret-seven']
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertNotIn("synthetic-secret", common.redact(sample))

    def test_recursive_json_and_env(self):
        data = {"config": {"password": "sentinel-a"}, "event": json.dumps({"api_key": "sentinel-b"}), "Environment": {"USER_VALUE": "sentinel-c"}, "tags": [{"Key": "token", "Value": "sentinel-d"}], "NextToken": "page-marker", "resource": "arn:aws:ecs:region:account:service/service-name"}
        out = common.sanitize(data)
        self.assertNotIn("sentinel", json.dumps(out))
        self.assertEqual(out["NextToken"], "page-marker")
        self.assertEqual(out["resource"], data["resource"])

    @patch("doctor_common.subprocess.run")
    def test_json_is_not_tail_truncated(self, run):
        run.return_value = CompletedProcess([], 0, json.dumps({"items": list(range(1500)), "password": "sentinel"}), "")
        result = common.run_command(["example"], text_limit=10)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["data"]["items"]), 1500)
        self.assertNotIn("sentinel", json.dumps(result))
        self.assertEqual(run.call_args.kwargs["env"]["AWS_PAGER"], "")

    @patch("doctor_common.subprocess.run")
    def test_invalid_json_and_timeout_fail(self, run):
        run.return_value = CompletedProcess([], 0, "broken", "")
        self.assertFalse(common.run_command(["example"])["ok"])
        run.side_effect = TimeoutExpired(["example"], 1)
        self.assertFalse(common.run_command(["example"], timeout=1)["ok"])

    @patch("doctor_common.subprocess.run")
    def test_text_clipping_is_explicit(self, run):
        run.return_value = CompletedProcess([], 0, "0123456789", "")
        result = common.run_command(["example"], parse_json=False, text_limit=4)
        self.assertEqual(result["data"], "6789")
        self.assertTrue(result["truncated"])
        self.assertEqual(common.collect_status(result), "partial")

    def test_status_and_atomic_sanitized_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "out.json"
            code = common.emit_result({"raw": [{"ok": True}, {"ok": False, "error": "token=sentinel"}]}, path)
            self.assertEqual(code, 1)
            result = json.loads(path.read_text())
            self.assertFalse(result["collection"]["complete"])
            self.assertNotIn("sentinel", path.read_text())
            self.assertEqual(len(list(Path(folder).iterdir())), 1)

    def test_explicit_failed_is_preserved(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(common.emit_result({"status": "failed", "blockers": ["missing auth"]}), 2)

    def test_authorization_assignment_hides_entire_value(self):
        self.assertNotIn('synthetic-api-secret', common.redact('Authorization=Bearer synthetic-api-secret'))

    @patch('doctor_common.run_command')
    def test_ecs_missing_resources_and_failures_are_not_success(self, run):
        command = ['aws', 'ecs', 'describe-services', '--services', 'one', '--query', 'services[].{serviceName:serviceName}']
        for payload in ({'items': [], 'failures': [{'reason': 'MISSING'}]}, {'items': [], 'failures': []}):
            run.return_value = {'ok': True, 'data': payload}
            result = common.run_ecs_read(command)
            self.assertFalse(result['ok'])
            self.assertIn('failures:failures', run.call_args.args[0][-1])
        run.return_value = {'ok': True, 'data': {'items': [{'serviceName': 'one'}], 'failures': []}}
        self.assertTrue(common.run_ecs_read(command)['ok'])


if __name__ == "__main__":
    unittest.main()
