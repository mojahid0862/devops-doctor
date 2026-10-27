import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import devops_doctor_preflight as preflight


class PreflightTests(unittest.TestCase):
    def test_default_local_does_not_authenticate(self):
        with patch.object(preflight, "git_context", return_value={"available": False}), \
             patch.object(preflight, "optional_tool_context", return_value={"available": False}), \
             patch.object(preflight, "glab_context") as glab, patch.object(preflight, "aws_context") as aws:
            result = preflight.build_report(preflight.parse_args([]))
        glab.assert_not_called()
        aws.assert_not_called()
        self.assertEqual(result["status"], "complete")
        self.assertNotIn("aws_ready", result["summary"])

    def test_gitlab_only_stops_on_auth_failure(self):
        with patch.object(preflight.shutil, "which", return_value="glab"), \
             patch.object(preflight, "run", return_value={"ok": False, "error": "authentication rejected"}) as run, \
             patch.object(preflight, "aws_context") as aws, patch.object(preflight, "git_context") as git:
            result = preflight.build_report(preflight.parse_args(["--scope", "gitlab"]))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["blockers"][0]["reason"], "authentication rejected")
        run.assert_called_once_with(["glab", "auth", "status"], timeout=25)
        aws.assert_not_called()
        git.assert_not_called()

    def test_aws_scope_honors_profile_and_region(self):
        response = {"ok": True, "data": {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/example"}}
        with patch.object(preflight.shutil, "which", return_value="aws"), \
             patch.object(preflight, "run_json", return_value=response) as run:
            result = preflight.build_report(preflight.parse_args(["--scope", "aws", "--profile", "test", "--region", "eu-west-1"]))
        command = run.call_args.args[0]
        self.assertEqual(command[-4:], ["--profile", "test", "--region", "eu-west-1"])
        self.assertEqual(result["status"], "complete")
        self.assertNotIn("example", json.dumps(result))

    def test_json_is_parsed_before_display_truncation(self):
        payload = {"padding": "a" * 3000, "Account": "123456789012"}
        with patch("doctor_common.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")):
            result = preflight.run_json(["mock", "json"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"], payload)

    def test_missing_requested_cli_fails(self):
        with patch.object(preflight.shutil, "which", return_value=None):
            result = preflight.build_report(preflight.parse_args(["--scope", "aws"]))
        self.assertEqual(result["status"], "failed")


if __name__ == "__main__":
    unittest.main()
