import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import aws_stack_snapshot as stack


def arguments(*values):
    return stack.parse_args(["--region", "eu-west-1", *values])


class StackTests(unittest.TestCase):
    def test_authentication_failure_stops_service_calls(self):
        with patch.object(stack, "aws_json", return_value={"ok": False, "error": "ExpiredToken"}) as command, \
             patch.dict(stack.COLLECTORS, {"rds": lambda args: self.fail("collector called")}):
            result = stack.build_report(arguments("--services", "rds"))
        command.assert_called_once()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["collection"]["complete"])

    def test_db_and_cache_filters_are_request_filters(self):
        for collector, flag, option in ((stack.collect_rds, "--db", "--db-instance-identifier"),
                                        (stack.collect_elasticache, "--cache", "--cache-cluster-id")):
            with self.subTest(flag=flag), patch.object(stack, "aws_json", return_value={"ok": True, "data": []}) as command:
                collector(arguments(flag, "one-resource"))
            command.assert_called_once()
            self.assertIn(option, command.call_args.args[0])
            self.assertIn("one-resource", command.call_args.args[0])

    def test_bucket_limit_reports_coverage(self):
        def command(base, *args, **kwargs):
            if base[1] == "list-buckets":
                return {"ok": True, "data": {"Buckets": [{"Name": name} for name in ("one", "two", "three")]}}
            return {"ok": True, "data": {}}
        with patch.object(stack, "aws_json", side_effect=command) as run:
            result = stack.collect_s3(arguments("--max-buckets", "2"))
        self.assertEqual(run.call_count, 7)
        self.assertEqual(result["coverage"]["inspected"], 2)
        self.assertTrue(result["coverage"]["truncated"])
        self.assertIsNone(result["coverage"]["total_known"])

    def test_truncated_snapshot_cannot_be_complete(self):
        with patch.object(stack, "aws_json", return_value={"ok": True, "data": {"Account": "123456789012"}}), \
             patch.dict(stack.COLLECTORS, {"s3": lambda args: {"buckets": {"ok": True}, "coverage": {"truncated": True}}}):
            result = stack.build_report(arguments("--services", "s3"))
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["collection"]["complete"])
        self.assertEqual(result["scope"]["account_id"], "123456789012")

    def test_concurrent_collectors_respect_worker_bound(self):
        lock = threading.Lock()
        active = peak = 0
        def collector(args):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return {"probe": {"ok": True, "data": []}}
        with patch.object(stack, "aws_json", return_value={"ok": True, "data": {"Account": "123456789012"}}), \
             patch.dict(stack.COLLECTORS, {key: collector for key in ("rds", "s3", "ecr", "lambda")}):
            result = stack.build_report(arguments("--services", "rds,s3,ecr,lambda", "--max-workers", "2"))
        self.assertEqual(peak, 2)
        self.assertEqual(result["status"], "complete")

    def test_all_service_failures_are_failed_despite_auth_success(self):
        with patch.object(stack, "aws_json", return_value={"ok": True, "data": {"Account": "123456789012"}}), \
             patch.dict(stack.COLLECTORS, {"rds": lambda args: {"ok": False, "error": "AccessDenied"}}):
            result = stack.build_report(arguments("--services", "rds"))
        self.assertEqual(result["status"], "failed")


if __name__ == "__main__":
    unittest.main()
