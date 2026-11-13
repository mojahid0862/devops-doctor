import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import aws_log_correlation as logs
import doctor_common as common


ACCOUNT = "123456789012"
GROUPS = ("/aws/lambda/orders", "/ecs/payments")
SELECTOR = "trace-private-123"
AWS = "aws.exe" if os.name == "nt" else "/usr/bin/aws"
BASE = ["--account-id", ACCOUNT, "--region", "ap-south-1", "--start", "2026-11-13T06:00:00Z",
        "--end", "2026-11-13T06:15:00Z"]


def arguments(*extra, groups=GROUPS):
    return BASE + [part for group in groups for part in ("--log-group", group)] + list(extra)


def ok(data):
    return {"ok": True, "data": data}


def completed(rows, **fields):
    return ok({"status": "Complete", "results": rows, **fields})


def row(args, offset, group, request, failure=False, **extras):
    fields = {"event_ms": str(args.start * 1000 + offset), "@log": f"{ACCOUNT}:{group}",
              "request_id": request, "correlation_id": SELECTOR, "failure": str(int(failure)), **extras}
    return [{"field": field, "value": value} for field, value in fields.items()]


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.args = logs.parse_args(arguments("--correlation-id", SELECTOR))

    def collect(self, *responses, args=None):
        initial = [ok({"Account": ACCOUNT}), ok({"queryId": "test-query"})]
        with patch.object(logs, "run_command", side_effect=initial + list(responses)) as runner, \
                patch.object(logs.time, "sleep"):
            report = logs.build_report(args or self.args, AWS)
        commands = [call.args[0][2] for call in runner.call_args_list]
        return report, commands

    def test_main_reports_ordered_redacted_cross_service_evidence_and_separate_counts(self):
        argv = arguments("--profile", "dev", "--correlation-id", SELECTOR, "--max-samples", "3")
        rows = [
            row(self.args, 9, GROUPS[1], "private-r1", True),
            row(self.args, 7, GROUPS[1], "private-r2", True),
            row(self.args, 4, GROUPS[0], "private-r1", True, **{"@message": "secret-payload", "@ptr": "private-pointer"}),
            row(self.args, 3, GROUPS[0], ""),
        ]
        responses = [ok({"Account": ACCOUNT}), ok({"queryId": "test-query"}),
                     ok({"status": "Running", "results": [row(self.args, 1, GROUPS[0], "ignored-running")]}),
                     completed(rows, statistics={"recordsScanned": 30.0, "recordsMatched": 4.0,
                                                 "bytesScanned": 2048.0, "logGroupsScanned": 2.0})]
        output = io.StringIO()
        with patch.object(logs.shutil, "which", return_value=AWS), patch.object(logs.time, "sleep"), \
                patch.object(logs, "run_command", side_effect=responses) as runner, redirect_stdout(output):
            self.assertEqual(logs.main(argv), 0)
        payload = output.getvalue()
        report = json.loads(payload)
        summary = report["summary"]
        self.assertEqual(report["status"], "complete")
        self.assertTrue(report["collection"]["complete"])
        self.assertEqual(report["coverage"]["source_event_coverage"], "unverified")
        self.assertEqual(report["coverage"]["samples_omitted"], 1)
        self.assertEqual(summary["unique_request_ids"], 2)
        self.assertEqual(summary["unique_failed_request_ids"], 2)
        self.assertEqual(summary["unique_correlation_ids"], 1)
        self.assertEqual(summary["unique_failed_correlation_ids"], 1)
        self.assertEqual(summary["failure_rows"], 3)
        self.assertEqual(summary["rows_without_request_id"], 1)
        self.assertEqual(summary["result_rows"], 4)
        self.assertEqual(summary["observed_log_groups"], list(GROUPS))
        self.assertEqual(report["query"]["statistics"], {"bytes_scanned": 2048.0, "log_groups_scanned": 2.0,
                                                         "records_matched": 4.0, "records_scanned": 30.0})
        samples = report["evidence"]["samples"]
        self.assertEqual([item["log_group"] for item in samples], [GROUPS[0], GROUPS[0], GROUPS[1]])
        self.assertEqual([item["timestamp"] for item in samples], sorted(item["timestamp"] for item in samples))
        self.assertEqual({item["correlation_alias"] for item in samples}, {"c1"})
        for value in (SELECTOR, "private-r1", "private-r2", "secret-payload", "private-pointer", "ignored-running"):
            self.assertNotIn(value, payload)
        commands = [call.args[0] for call in runner.call_args_list]
        self.assertEqual([command[2] for command in commands],
                         ["get-caller-identity", "start-query", "get-query-results", "get-query-results"])
        query_command = commands[1]
        group_arg = query_command.index("--log-group-names")
        self.assertEqual(query_command[group_arg + 1:group_arg + 3], list(GROUPS))
        query = query_command[query_command.index("--query-string") + 1]
        self.assertIn(f'corr_id = "{SELECTOR}"', query)
        self.assertIn(f"event_ms < {self.args.end * 1000}", query)
        self.assertIn("display event_ms, @log, request_id, correlation_id, failure", query)
        for call in runner.call_args_list:
            self.assertIn("--no-paginate", call.args[0])
            self.assertEqual(call.args[0][call.args[0].index("--region") + 1], "ap-south-1")
            self.assertEqual(call.args[0][call.args[0].index("--profile") + 1], "dev")
            self.assertEqual(call.kwargs["aws_max_attempts"], 1)
            self.assertTrue(call.kwargs["aws_ignore_configured_endpoints"])

    def test_exact_request_and_correlation_match_and_out_of_scope_rows_are_partial(self):
        args = logs.parse_args(arguments("--request-id", "r-allowed", "--correlation-id", SELECTOR))
        self.assertIn(f'req_id = "r-allowed" and corr_id = "{SELECTOR}"', logs.query_string(args))
        good = row(args, 1, GROUPS[0], "r-allowed", True)
        rows = [good, row(args, 2, GROUPS[0], "r-other"), row(args, 3, "/unrequested", "r-allowed"),
                row(args, (args.end - args.start) * 1000, GROUPS[0], "r-allowed"), ["malformed"]]
        report, _ = self.collect(completed(rows), args=args)
        self.assertEqual(report["status"], "partial")
        self.assertFalse(report["coverage"]["complete"])
        self.assertIn("invalid_or_out_of_scope_rows", report["coverage"]["reasons"])
        self.assertEqual(report["summary"]["invalid_rows"], 4)
        self.assertEqual(report["summary"]["unique_failed_request_ids"], 1)

    def test_same_request_alias_and_failure_count_across_groups(self):
        rows = [row(self.args, i, group, "private-r1", True) for i, group in enumerate(GROUPS)]
        report, _ = self.collect(completed(rows))
        self.assertEqual(report["summary"]["unique_request_ids"], 1)
        self.assertEqual(report["summary"]["unique_failed_request_ids"], 1)
        self.assertEqual([sample["request_alias"] for sample in report["evidence"]["samples"]], ["r1", "r1"])

    def test_query_uses_first_valid_id_and_skips_empty_failure_fields(self):
        query = logs.query_string(self.args)
        for fields, fallback, alias in (
            (("requestId", "request_id", "RequestId"), "text_req", "req_id"),
            (("correlationId", "correlation_id", "CorrelationId"), "text_corr", "corr_id"),
        ):
            with self.subTest(alias=alias):
                pattern = r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}"
                clauses = ", ".join(f"payload.{field} like /^{pattern}$/, payload.{field}" for field in fields)
                self.assertIn(f'case({clauses}, coalesce({fallback}, "")) as {alias}', query)
        self.assertIn("isempty(payload.level) = 0, payload.level", query)
        self.assertIn("toInt(payload.statusCode), toInt(payload.status_code)", query)

    def test_empty_is_distinct_from_capped_or_missing_rows(self):
        report, _ = self.collect(completed([], statistics={"recordsMatched": 0}))
        self.assertEqual(report["summary"]["query_outcome"], "empty")
        self.assertTrue(report["collection"]["complete"])
        self.assertEqual(report["summary"]["unique_request_ids"], 0)
        report, _ = self.collect(completed([], statistics={"recordsMatched": 4}))
        self.assertEqual(report["summary"]["query_outcome"], "completed")
        self.assertFalse(report["collection"]["complete"])
        self.assertTrue(report["coverage"]["truncated"])
        report, _ = self.collect(completed([], statistics={"recordsMatched": 0, "logGroupsScanned": 1}))
        self.assertEqual(report["status"], "partial")
        self.assertIn("fewer_log_groups_scanned_than_requested", report["coverage"]["reasons"])
        self.assertEqual(report["summary"]["result_rows"], 0)
        report, _ = self.collect(ok({"status": "Complete"}))
        self.assertEqual(report["status"], "failed")
        self.assertIsNone(report["summary"]["result_rows"])

    def test_result_cap_continuation_and_stats_mismatch_are_reported(self):
        args = logs.parse_args(arguments("--correlation-id", SELECTOR, "--max-results", "1"))
        event = row(args, 1, GROUPS[0], "private-r1")
        cases = (
            (args, {}, "result_limit_reached"),
            (self.args, {"nextToken": "private-page"}, "additional_results_available"),
            (self.args, {"statistics": {"recordsMatched": 2}}, "statistics_exceed_returned_rows"),
            (self.args, {"statistics": {"recordsMatched": 0}}, "matched_records_below_returned_rows"),
            (self.args, {"statistics": {"resultCount": 0}}, "service_result_count_below_returned_rows"),
        )
        for scope, extra, reason in cases:
            with self.subTest(reason=reason):
                report, commands = self.collect(completed([event], **extra), args=scope)
                self.assertEqual(report["status"], "partial")
                self.assertIn(reason, report["coverage"]["reasons"])
                self.assertEqual(commands.count("get-query-results"), 1)
                self.assertNotIn("private-page", json.dumps(report))

    def test_terminal_failure_cancelled_and_timeout(self):
        for state, outcome in (("Failed", "failed"), ("Cancelled", "cancelled"), ("Timeout", "timed_out")):
            with self.subTest(state=state):
                report, commands = self.collect(ok({"status": state, "results": []}))
                self.assertEqual(report["query"]["status"], state)
                self.assertEqual(report["summary"]["query_outcome"], outcome)
                self.assertIsNone(report["summary"]["result_rows"])
                self.assertFalse(report["collection"]["complete"])
                self.assertNotIn("stop-query", commands)

    def test_poll_limit_reports_active_state_and_stops_once(self):
        args = logs.parse_args(arguments("--correlation-id", SELECTOR, "--max-polls", "2"))
        for state in ("Scheduled", "Running"):
            with self.subTest(state=state):
                active = ok({"status": state, "results": [row(args, 1, GROUPS[0], "private-r1")]})
                report, commands = self.collect(active, active, ok({"success": True}), args=args)
                self.assertEqual(report["summary"]["query_outcome"], state.lower())
                self.assertIsNone(report["summary"]["result_rows"])
                self.assertEqual(report["evidence"]["samples"], [])
                self.assertEqual(report["query"]["polls"], 2)
                self.assertEqual(report["query"]["cleanup"], "stop_acknowledged")
                self.assertEqual(commands.count("stop-query"), 1)

    def test_deadline_reserves_cleanup_time_and_reports_unconfirmed_stop(self):
        clock = 0.0

        def respond(command, **kwargs):
            nonlocal clock
            operation = command[2]
            if operation == "get-caller-identity":
                return ok({"Account": ACCOUNT})
            if operation == "start-query":
                return ok({"queryId": "test-query"})
            if operation == "get-query-results":
                clock += kwargs["timeout"]
                return ok({"status": "Running"})
            self.assertEqual(operation, "stop-query")
            self.assertEqual(kwargs["timeout"], logs.CLEANUP_SECONDS)
            return {"ok": False, "error": "AccessDeniedException: stop failed"}

        with patch.object(logs.time, "monotonic", side_effect=lambda: clock), \
                patch.object(logs.time, "sleep"), patch.object(logs, "run_command", side_effect=respond) as runner:
            report = logs.build_report(self.args, AWS)
        self.assertEqual(report["summary"]["query_outcome"], "timed_out")
        self.assertEqual(report["query"]["status"], "Running")
        self.assertEqual(report["query"]["cleanup"], "stop_unconfirmed")
        self.assertFalse(report["collection"]["complete"])
        self.assertEqual(runner.call_count, 4)

    def test_access_denied_is_redacted_and_attempts_cleanup(self):
        report, commands = self.collect({"ok": False, "error": "AccessDeniedException: secret-error-body"},
                                        ok({"success": True}))
        self.assertEqual(report["summary"]["query_outcome"], "access_denied")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(commands[-1], "stop-query")
        self.assertNotIn("secret-error-body", json.dumps(report))

    def test_wrong_account_never_starts_query(self):
        with patch.object(logs, "run_command", return_value=ok({"Account": "999999999999"})) as runner:
            report = logs.build_report(self.args, AWS)
        runner.assert_called_once()
        self.assertEqual(report["summary"]["query_outcome"], "account_mismatch")

    def test_unconfirmed_start_after_cli_timeout_does_not_resubmit(self):
        responses = [ok({"Account": ACCOUNT}), {"ok": False, "error": "timeout after 8s"}]
        with patch.object(logs, "run_command", side_effect=responses) as runner:
            report = logs.build_report(self.args, AWS)
        self.assertEqual(report["summary"]["query_outcome"], "timed_out")
        self.assertTrue(report["query"]["start_unconfirmed"])
        self.assertEqual(runner.call_count, 2)

    def test_output_byte_cap_preserves_counts_and_truncation(self):
        groups = tuple(f"/group{i}/" + "x" * 450 for i in range(4))
        args = logs.parse_args(arguments("--correlation-id", SELECTOR, "--max-output-bytes", "4096",
                                        "--max-samples", "20", groups=groups))
        rows = [row(args, i, groups[i % len(groups)], "private-r1") for i in range(20)]
        report, _ = self.collect(completed(rows, statistics={"recordsMatched": 20}), args=args)
        report = logs.bounded_output(report, args.max_output_bytes)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(logs.emit_result(report), 1)
        payload = output.getvalue()
        self.assertLessEqual(len(payload.replace("\n", os.linesep).encode("utf-8")), args.max_output_bytes)
        actual = json.loads(payload)
        self.assertIn("output_byte_limit", actual["coverage"]["reasons"])
        self.assertEqual(actual["summary"]["result_rows"], 20)
        self.assertEqual(actual["query"]["statistics"]["records_matched"], 20)
        self.assertFalse(actual["collection"]["complete"])

    def test_invalid_scope_or_selectors_are_rejected_before_cli_execution(self):
        cases = (
            arguments(),
            arguments("--request-id", 'a" | limit 999'),
            arguments("--request-id", "req-1", groups=("--query-string",)),
            arguments("--request-id", "req-1", groups=(GROUPS[0], GROUPS[0])),
            arguments("--request-id", "req-1", "--max-log-groups", "1"),
            arguments("--request-id", "req-1", "--max-window-minutes", "1"),
            arguments("--request-id", "req-1", "--max-polls", "31"),
            arguments("--request-id", "req-1", "--end", "2026-11-13T06:15:00"),
        )
        for argv in cases:
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()), patch.object(logs, "run_command") as runner:
                with self.assertRaises(SystemExit) as failure:
                    logs.main(argv)
                self.assertEqual(failure.exception.code, 2)
                runner.assert_not_called()

    def test_shared_runner_aws_overrides_are_opt_in_and_subprocess_local(self):
        result = CompletedProcess(["aws"], 0, stdout="{}")
        overrides = {"AWS_MAX_ATTEMPTS": "5", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "false"}
        with patch.dict(common.os.environ, overrides), \
                patch.object(common.subprocess, "run", return_value=result) as subprocess:
            common.run_command(["aws"])
            common.run_command(["aws"], aws_max_attempts=1, aws_ignore_configured_endpoints=True)
            default_env, scoped_env = (call.kwargs["env"] for call in subprocess.call_args_list)
            for key, default, value in (("AWS_MAX_ATTEMPTS", "5", "1"),
                                        ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false", "true")):
                self.assertEqual(default_env[key], default)
                self.assertEqual(scoped_env[key], value)
                self.assertEqual(common.os.environ[key], default)
