import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import aws_security_findings as findings
import doctor_common as common


ACCOUNT = "123456789012"
REGION = "ap-south-1"
AWS = "aws.exe" if os.name == "nt" else "/usr/bin/aws"
BASE = ["--account-id", ACCOUNT, "--region", REGION, "--profile", "dev"]
DATE = "2026-11-13T06:00:00Z"


def ok(data):
    return {"ok": True, "data": data}


def error(message):
    return {"ok": False, "error": message}


def hub(api="hubv2"):
    return ok({"HubArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT}:{api}/default"})


def asff_or_ocsf(**changes):
    return {"Id": "finding-private-1", "ProductId": "product-private", "EventId": "private-event",
            "AccountId": ACCOUNT, "Region": REGION, "Severity": "High", "Status": "New",
            "CreatedAt": 1762019193000, "UpdatedAt": DATE,
            "Resources": [{"Id": "resource-private", "AlternateId": "arn:aws:s3:::private-bucket",
                           "Type": "Bucket", "Region": REGION, "Details": "secret-ignored"}],
            "Description": "secret-description", "Class": "Exposure", **changes}


def guard_finding(identifier="guard-1", **changes):
    return {"Id": identifier, "Arn": f"arn:aws:guardduty:{REGION}:{ACCOUNT}:detector/d1/finding/{identifier}",
            "AccountId": ACCOUNT, "Region": REGION, "Score": 9.5, "Archived": False, "CreatedAt": DATE,
            "FirstSeen": DATE, "Class": "AttackSequence:Example", "ResourceType": "Instance",
            "Resources": {"r0": {"InstanceId": "i-private", "AccessKeyId": "AKIAZZZZZZZZZZZZZZZZ"}},
            **changes}


def steps(*operations):
    return [ok({"Account": ACCOUNT}), *operations]


def detector_steps(*operations):
    return [ok({"DetectorIds": ["d1"], "NextToken": None}), ok({"Status": "ENABLED"}), *operations]


class SecurityFindingsTests(unittest.TestCase):
    def collect(self, responses, *extra):
        args = findings.parse_args(BASE + list(extra))
        with patch.object(findings, "cli_history_outcome", return_value=None), \
                patch.object(findings, "run_command", side_effect=responses) as runner:
            report, records = findings.build_report(args, AWS)
        return report, records, runner.call_args_list

    def command(self, call):
        command = call.args[0]
        body = json.loads(command[command.index("--cli-input-json") + 1]) if "--cli-input-json" in command else None
        return command[2], body

    def test_v2_and_guardduty_pagination_scope_details_and_redaction(self):
        token = 'synthetic/token+with="quotes"'
        responses = steps(
            hub(), ok({"Findings": [asff_or_ocsf()], "NextToken": token}),
            ok({"Findings": [asff_or_ocsf(), asff_or_ocsf(ProductId="second-product")], "NextToken": None}),
            *detector_steps(ok({"FindingIds": ["guard-1", "guard-1"], "NextToken": "guard-page-2"}),
                            ok({"Findings": [guard_finding()]}),
                            ok({"FindingIds": ["guard-1", "guard-2"]}),
                            ok({"Findings": [guard_finding("guard-2", Score=4.5, Archived=True)]})),
        )
        report, records, calls = self.collect(responses)
        commands = [self.command(call) for call in calls]
        self.assertEqual([operation for operation, _ in commands], [
            "get-caller-identity", "describe-security-hub-v2", "get-findings-v2", "get-findings-v2",
            "list-detectors", "get-detector", "list-findings", "get-findings", "list-findings", "get-findings",
        ])
        self.assertEqual(commands[3][1]["NextToken"], token)
        self.assertEqual(commands[3][1]["MaxResults"], 25)
        filters = commands[3][1]["Filters"]["CompositeFilters"][0]
        self.assertEqual(filters["Operator"], "AND")
        self.assertEqual({item["FieldName"]: item["Filter"]["Value"] for item in filters["StringFilters"]},
                         {"cloud.account.uid": ACCOUNT, "cloud.region": REGION})
        self.assertEqual(commands[6][1]["FindingCriteria"]["Criterion"],
                         {"accountId": {"Equals": [ACCOUNT]}, "region": {"Equals": [REGION]}})
        self.assertEqual(commands[8][1]["NextToken"], "guard-page-2")
        self.assertEqual(commands[9][1]["FindingIds"], ["guard-2"])
        for call in calls:
            self.assertIn("--no-paginate", call.args[0])
            self.assertIn(REGION, call.args[0])
            self.assertIn("dev", call.args[0])
            self.assertEqual(call.kwargs["aws_max_attempts"], 1)
            self.assertTrue(call.kwargs["aws_ignore_configured_endpoints"])
            self.assertFalse(call.kwargs["sanitize_json"])
            self.assertGreater(call.kwargs["timeout"], 0)
        self.assertEqual(report["status"], "complete")
        services = report["summary"]["services"]
        self.assertEqual(services["securityhub"]["by_severity"], {"HIGH": 2})
        self.assertEqual(services["securityhub"]["priority_counts"], {"exposures": 2})
        self.assertEqual(services["securityhub"]["duplicate_findings"], 1)
        self.assertEqual(services["guardduty"]["by_severity"], {"CRITICAL": 1, "MEDIUM": 1})
        self.assertEqual(services["guardduty"]["duplicate_findings"], 2)
        hub_records = [record for record in records if record["source_service"] == "securityhub"]
        self.assertEqual(records[0]["priority"], "attack_sequences")
        self.assertEqual(hub_records[0]["id"], "finding-private-1")
        self.assertEqual(hub_records[0]["timestamps"]["created_at"], 1762019193000)
        self.assertEqual(records[-1]["status"], "ARCHIVED")
        self.assertEqual(records[-1]["resources"], [{"id": "i-private", "type": "EC2Instance"}])
        for text in ("finding-private", "resource-private", "private-bucket", "guard-1", "synthetic/token"):
            self.assertNotIn(text, json.dumps(report))
        for text in ("secret-description", "secret-ignored", "AKIAZZ"):
            self.assertNotIn(text, json.dumps(records))

    def test_cspm_has_distinct_api_and_preserves_workflow_and_record_state(self):
        report, records, calls = self.collect(steps(hub("hub"), ok({"Findings": [
            asff_or_ocsf(RecordState="ARCHIVED", Status="RESOLVED", Score=70, Class=None),
        ]})), "--service", "securityhub", "--securityhub-api", "cspm")
        self.assertEqual(report["status"], "complete")
        self.assertEqual(self.command(calls[1])[0], "describe-hub")
        operation, body = self.command(calls[2])
        self.assertEqual(operation, "get-findings")
        self.assertEqual(body["Filters"], {"AwsAccountId": [{"Value": ACCOUNT, "Comparison": "EQUALS"}],
                                           "Region": [{"Value": REGION, "Comparison": "EQUALS"}]})
        self.assertEqual(records[0]["record_state"], "ARCHIVED")
        self.assertEqual(records[0]["status"], "RESOLVED")

    def test_empty_is_distinct_from_disabled_and_not_configured(self):
        cases = [
            ("securityhub", [hub(), ok({"Findings": []})], "empty", "complete"),
            ("guardduty", detector_steps(ok({"FindingIds": []})), "empty", "complete"),
            ("securityhub", [error("ResourceNotFoundException: disabled")], "not_configured", "partial"),
            ("guardduty", [ok({"DetectorIds": []})], "not_configured", "partial"),
            ("guardduty", [ok({"DetectorIds": ["d1"]}), ok({"Status": "DISABLED"})], "disabled", "partial"),
        ]
        for service, responses, outcome, overall in cases:
            with self.subTest(service=service, outcome=outcome):
                report, records, calls = self.collect(steps(*responses), "--service", service)
                self.assertEqual(len(calls), len(responses) + 1)
                self.assertEqual(report["status"], overall)
                self.assertEqual(report["summary"]["services"][service]["outcome"], outcome)
                self.assertEqual(records, [])

    def test_denied_and_failure_are_redacted_and_distinct(self):
        for raw, outcome in (("AccessDeniedException", "access_denied"), ("ServiceUnavailableException", "api_failure")):
            with self.subTest(outcome=outcome):
                report, records, _ = self.collect(steps(hub(), error(raw + ": private-aws-error")),
                                                  "--service", "securityhub")
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["blockers"], [{"scope": "securityhub", "reason": outcome}])
                self.assertNotIn("private-aws-error", json.dumps(report))
                self.assertEqual(records, [])

    def test_account_mismatch_stops_before_discovery(self):
        report, records, calls = self.collect([ok({"Account": "999999999999"})])
        self.assertEqual(report["blockers"], [{"scope": "identity", "reason": "account_mismatch"}])
        self.assertEqual(len(calls), 1)
        self.assertEqual(records, [])

    def test_expired_session_skips_remaining_sources(self):
        report, _, calls = self.collect(steps(hub(), error("ExpiredTokenException")))
        self.assertEqual(len(calls), 3)
        self.assertEqual(report["summary"]["services"]["guardduty"]["reasons"],
                         ["skipped_after_authentication_failure"])

    def test_missing_or_out_of_scope_rows_and_incomplete_fields_never_read_complete(self):
        report, records, _ = self.collect(steps(hub(), ok({"Findings": [
            None, asff_or_ocsf(Region="us-east-1"), asff_or_ocsf(AccountId="999999999999"),
            asff_or_ocsf(ProductId=None),
            asff_or_ocsf(Severity=None, Resources=None, UpdatedAt="bad", CreatedAt=None),
        ]})), "--service", "securityhub")
        self.assertEqual(report["status"], "partial")
        result = report["summary"]["services"]["securityhub"]
        self.assertEqual(result["invalid_findings"], 4)
        self.assertIn("finding_provider_unverified", result["reasons"])
        self.assertIn("finding_fields_incomplete", result["reasons"])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["timestamps"], {})
        malformed, _, _ = self.collect(steps(hub(), ok({"Findings": {}})), "--service", "securityhub")
        self.assertEqual(malformed["summary"]["services"]["securityhub"]["outcome"], "malformed_response")

    def test_conflicting_duplicates_keep_newest_and_mark_partial(self):
        older = asff_or_ocsf(UpdatedAt="2026-11-13T04:00:00Z", Severity="Low")
        report, records, _ = self.collect(steps(hub(), ok({"Findings": [older, asff_or_ocsf(), older]})),
                                          "--service", "securityhub")
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["summary"]["services"]["securityhub"]["reasons"], ["conflicting_duplicate"])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["severity"]["label"], "High")

    def test_findings_and_page_caps_and_repeated_continuation(self):
        first = ok({"Findings": [asff_or_ocsf()], "NextToken": "first"})
        cases = [
            (["--max-findings", "1"], [first], "finding_limit"),
            (["--max-pages", "1"], [first], "page_limit"),
            ([], [first, first], "invalid_or_repeated_continuation"),
            ([], [ok({"Findings": [asff_or_ocsf()], "NextToken": 14})], "invalid_or_repeated_continuation"),
            (["--page-size", "1"], [ok({"Findings": [asff_or_ocsf(), asff_or_ocsf(Id="other")]})],
             "page_exceeded_requested_limit"),
        ]
        for flags, responses, reason in cases:
            with self.subTest(reason=reason):
                report, records, calls = self.collect(steps(hub(), *responses), "--service", "securityhub", *flags)
                result = report["summary"]["services"]["securityhub"]
                self.assertEqual(result["outcome"], "truncated")
                self.assertTrue(result["truncated"])
                self.assertIn(reason, result["reasons"])
                self.assertEqual(len(records), 1)
                self.assertEqual(len(calls), 2 + len(responses))

    def test_guardduty_missing_details_and_unrequested_id_remain_partial(self):
        report, records, calls = self.collect(steps(*detector_steps(
            ok({"FindingIds": ["guard-1", "guard-2"]}),
            ok({"Findings": [guard_finding(), guard_finding("wrong-id")]}),
        )), "--service", "guardduty")
        self.assertEqual(len(calls), 5)
        self.assertEqual(len(records), 1)
        result = report["summary"]["services"]["guardduty"]
        self.assertEqual(result["outcome"], "truncated")
        self.assertIn("listed_finding_details_missing", result["reasons"])
        self.assertIn("unrequested_finding_details", result["reasons"])

    def test_guardduty_rejects_conflicting_finding_arn_and_keeps_sequence_resource_scope(self):
        finding = guard_finding(Resources=None, SequenceResources=[
            {"Id": "resource-other-region", "Type": "EC2_INSTANCE", "Region": "us-east-1",
             "OwnerAccount": "999999999999"},
        ])
        conflict = guard_finding("guard-2")
        conflict["Arn"] = conflict["Arn"].replace(REGION, "us-east-1")
        report, records, calls = self.collect(steps(*detector_steps(
            ok({"FindingIds": ["guard-1", "guard-2"]}), ok({"Findings": [finding, conflict]}),
        )), "--service", "guardduty")
        self.assertIn("SequenceResources:Service.Sequence.Resources", calls[-1].args[0][
            calls[-1].args[0].index("--query") + 1])
        self.assertEqual(report["status"], "partial")
        self.assertFalse(report["coverage"]["event_origin_verified"])
        self.assertTrue(report["coverage"]["related_resources_may_span_accounts_or_regions"])
        self.assertEqual([record["id"] for record in records], ["guard-1"])
        self.assertEqual(records[0]["resources"][0]["region"], "us-east-1")
        self.assertEqual(records[0]["resources"][0]["account_id"], "999999999999")

    def test_cli_history_preflight_blocks_sensitive_calls_and_accepts_unset(self):
        args = findings.parse_args(BASE)
        for response, reason in (
            (ok("enabled"), "cli_history_enabled"),
            (ok("unexpected"), "cli_history_unverified"),
            (error("config error with private data"), "cli_history_unverified"),
        ):
            with self.subTest(reason=reason), patch.object(findings, "run_command", return_value=response) as runner:
                report, records = findings.build_report(args, AWS)
                runner.assert_called_once()
                self.assertEqual(runner.call_args.args[0][1:4], ["configure", "get", "cli_history"])
                self.assertEqual(report["blockers"], [{"scope": "aws_cli", "reason": reason}])
                self.assertEqual(records, [])
        with patch.object(findings, "run_command", return_value={
            "ok": False, "returncode": 1, "error": "command exited 1",
        }):
            self.assertIsNone(findings.cli_history_outcome(AWS, "dev", REGION, 2))
        with patch.object(findings, "run_command", return_value=ok("disabled")):
            self.assertIsNone(findings.cli_history_outcome(AWS, "dev", REGION, 2))

    def test_shared_deadline_stops_second_service_and_preserves_first_page(self):
        with patch.object(findings.time, "monotonic", side_effect=[0, 0, 0, 1, 2, 60, 60]):
            report, records, calls = self.collect(steps(hub(), ok({
                "Findings": [asff_or_ocsf()], "NextToken": "one-more",
            })))
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[-1].kwargs["timeout"], 58)
        self.assertEqual(len(records), 1)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["summary"]["services"]["securityhub"]["outcome"], "timed_out")
        self.assertEqual(report["summary"]["services"]["guardduty"]["outcome"], "timed_out")

    def test_protected_evidence_is_bounded_and_never_prints_ids(self):
        rows = [asff_or_ocsf(), asff_or_ocsf(Id="second", Resources=[
            {"Id": f"resource-{n}-" + "x" * 400} for n in range(15)
        ])]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "evidence"
            output = io.StringIO()
            with patch.object(findings.shutil, "which", return_value=AWS), redirect_stdout(output), \
                    patch.object(findings, "cli_history_outcome", return_value=None), \
                    patch.object(findings, "run_command", side_effect=steps(hub(), ok({"Findings": rows}))):
                exit_code = findings.main(BASE + ["--service", "securityhub", "--evidence-dir", str(target),
                                                   "--max-output-bytes", "4096"])
            self.assertEqual(exit_code, 1)
            payload = output.getvalue()
            report = json.loads(payload)
            self.assertLessEqual(len(payload.replace("\n", os.linesep).encode("utf-8")), 4096)
            self.assertFalse(report["collection"]["complete"])
            self.assertNotIn("finding-private-1", payload)
            self.assertEqual(report["evidence"]["findings_omitted"], 1)
            path = target / "findings.json"
            evidence_bytes = path.read_bytes()
            self.assertLessEqual(len(evidence_bytes), 4096)
            evidence = json.loads(evidence_bytes)
            self.assertFalse(evidence["complete"])
            self.assertEqual(evidence["findings"][0]["id"], "finding-private-1")
            self.assertEqual(evidence["findings"][0]["resources"][0]["id"], "resource-private")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                findings.save_evidence(target, report, [], 4096)

    def test_shared_runner_preserves_legacy_defaults_and_result_contract(self):
        response = CompletedProcess(["aws"], 0, stdout='{"Password":"synthetic","NextToken":"original"}')
        base = {"AWS_MAX_ATTEMPTS": "4", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "false"}
        with patch.dict(common.os.environ, base), patch.object(common.subprocess, "run", return_value=response) as run:
            legacy = common.run_command(["aws"])
            projected = common.run_command(["aws"], timeout=3.5, aws_max_attempts=1,
                                           aws_ignore_configured_endpoints=True, sanitize_json=False)
            self.assertEqual(legacy["data"]["Password"], common.MASK)
            self.assertEqual(projected["data"]["Password"], "synthetic")
            self.assertTrue(legacy["truncated"])
            self.assertEqual(run.call_args_list[0].kwargs["env"]["AWS_MAX_ATTEMPTS"], "4")
            self.assertEqual(run.call_args.kwargs["env"]["AWS_MAX_ATTEMPTS"], "1")
            self.assertEqual(run.call_args.kwargs["env"]["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"], "true")
            self.assertEqual(common.os.environ["AWS_MAX_ATTEMPTS"], "4")
        output = io.StringIO()
        report = {"status": "partial", "generated_at": DATE, "Password": "synthetic"}
        with redirect_stdout(output):
            self.assertEqual(common.emit_result(report), 1)
        payload, code = common.result_payload(report)
        self.assertEqual((payload, code), (output.getvalue(), 1))
        self.assertNotIn("synthetic", payload)
