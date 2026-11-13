import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import cloudformation_review as cfn
import evidence_slice as evidence


def change(index, action, replacement=None, **extra):
    return {"Type": "Resource", "ResourceChange": {
        "LogicalResourceId": f"PrivateBucket{index}", "ResourceType": "AWS::S3::Bucket", "Action": action,
        "Replacement": replacement, "PhysicalResourceId": "private-physical-id", **extra,
    }}


def event(index, status, *, time=None, stack="private-stack", **extra):
    return {"EventId": f"private-event-{index}", "StackId": stack, "LogicalResourceId": "PrivateResource",
            "PhysicalResourceId": "private-physical-id", "ResourceType": "AWS::S3::Bucket",
            "Timestamp": time or f"2026-10-01T06:00:{index:02d}Z", "ResourceStatus": status,
            "OperationId": "private-operation", **extra}


class CloudFormationReviewTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def write(self, value, name="input.json"):
        path = self.root / name
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return path

    def invoke(self, mode, path, *args):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cfn.main([mode, "--file", str(path), *args])
        return code, json.loads(output.getvalue()), output.getvalue()

    def reasons(self, report):
        return {item["reason"] for item in report["blockers"]}

    def test_literal_template_findings_and_missing_validators(self):
        path = self.write({"Resources": {
            "PrivateBucket": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicRead"}},
            "PrivateDatabase": {"Type": "AWS::RDS::DBInstance", "Properties": {
                "StorageEncrypted": False, "PubliclyAccessible": True, "MasterUserPassword": "private-password",
            }},
            "PrivateVolume": {"Type": "AWS::EC2::Volume", "UpdateReplacePolicy": "Retain"},
            "PrivateGroup": {"Type": "AWS::EC2::SecurityGroupIngress", "Properties": {
                "CidrIp": "0.0.0.0/0", "IpProtocol": "tcp", "FromPort": 20, "ToPort": 25,
            }},
        }})
        rules = self.write("rule check { Resources EXISTS }", "test.guard")
        with patch.object(cfn.shutil, "which", return_value=None), patch.object(cfn.subprocess, "run") as run:
            code, report, payload = self.invoke("template", path, "--guard-rules", str(rules))
            run.assert_not_called()
        self.assertEqual(code, 1)
        self.assertEqual(report["validation"], {"cfn-lint": "unavailable", "cfn-guard": "unavailable"})
        self.assertEqual(report["summary"]["resources_reviewed"], 4)
        labels = {(item["rule"], item["severity"]) for item in report["findings"]}
        self.assertIn(("internet_wide_ingress", "high"), labels)
        self.assertIn(("public_acl_requested_effective_access_unverified", "high"), labels)
        self.assertIn(("at_rest_encryption_explicitly_disabled", "high"), labels)
        self.assertIn(("at_rest_encryption_not_declared_verify_defaults", "medium"), labels)
        self.assertIn(("state_retention_requires_review", "medium"), labels)
        self.assertNotIn("private-password", payload)
        self.assertNotIn("PrivateDatabase", payload)
        self.assertEqual(report["scope"]["source"]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "optional PyYAML is unavailable")
    def test_yaml_intrinsics_and_transform_are_unresolved_without_false_outcomes(self):
        path = self.write("""AWSTemplateFormatVersion: 2010-09-09
Transform: AWS::LanguageExtensions
Resources:
  Db:
    Type: AWS::RDS::DBInstance
    Condition: IsProd
    Properties:
      StorageEncrypted: !Ref EnableEncryption
      PubliclyAccessible: !If [IsProd, false, true]
      MasterUserPassword: '{{resolve:secretsmanager:private-secret}}'
  CustomThing:
    Type: Custom::PrivateName
    Properties:
      ServiceToken: !GetAtt Function.Arn
""", "template.yml")
        with patch.object(cfn.subprocess, "run") as run:
            code, report, payload = self.invoke("template", path)
            run.assert_not_called()
        self.assertEqual(code, 1)
        self.assertEqual(report["validation"]["cfn-lint"], "transform_not_evaluated")
        self.assertTrue({"transforms_not_expanded", "intrinsics_or_dynamic_references_unresolved",
                         "resource_conditions_not_evaluated", "custom_or_nested_resources_not_expanded"} <= self.reasons(report))
        self.assertFalse({"at_rest_encryption_explicitly_disabled", "public_database_requested_network_access_unverified"}
                         & {item["rule"] for item in report["findings"]})
        self.assertNotIn("private-secret", payload)
        self.assertNotIn("CustomThing", payload)
        self.assertNotIn("PrivateName", payload)
        _, parsed = cfn.read_document(path, "template", None)
        self.assertEqual(parsed["Resources"]["CustomThing"]["Properties"]["ServiceToken"],
                         {"Fn::GetAtt": ["Function", "Arn"]})

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "optional PyYAML is unavailable")
    def test_yaml_rejects_unsafe_tags_aliases_duplicate_keys_and_multiple_documents(self):
        for text in ("Resources: !!python/object:example {}", "Resources: &x {R: *x}",
                     "Resources: {}\nResources: {}", "Resources: {}\n---\nResources: {}"):
            with self.subTest(text=text):
                code, report, _ = self.invoke("template", self.write(text, "template.yaml"))
                self.assertEqual(code, 2)
                self.assertFalse(report["collection"]["complete"])

    def test_yaml_dependency_missing_is_an_explicit_gap(self):
        with patch.dict(sys.modules, {"yaml": None}):
            code, report, _ = self.invoke("template", self.write("Resources: {}", "template.yaml"))
        self.assertEqual(code, 2)
        self.assertIn("optional_yaml_parser_unavailable", self.reasons(report))

    def test_optional_validators_use_neutral_inputs_and_bounded_execution(self):
        path = self.write({"Metadata": {"cfn-lint": {"config": {"append_rules": ["private-code-path"]}}},
                           "Resources": {"Bucket": {"Type": "AWS::S3::Bucket", "Metadata": {"cfn-lint": {}}}}})
        rules = self.write("rule x { Resources EXISTS }", "rules.guard")
        executable = lambda tool: str(self.root / f"{tool}.exe")

        def mock_run(argv, **kwargs):
            self.assertEqual(kwargs["timeout"], 3)
            self.assertNotIn("AWS_ACCESS_KEY_ID", kwargs["env"])
            self.assertEqual(kwargs["env"]["AWS_EC2_METADATA_DISABLED"], "true")
            self.assertEqual(kwargs["stdout"], cfn.subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], cfn.subprocess.DEVNULL)
            staged = json.loads(Path(argv[-1]).read_text(encoding="utf-8"))
            if argv[0].endswith("cfn-lint.exe"):
                self.assertNotIn("Metadata", staged)
                self.assertNotIn("Metadata", staged["Resources"]["Bucket"])
                self.assertEqual(json.loads(Path(argv[2]).read_text(encoding="utf-8")), {})
                return CompletedProcess(argv, 0)
            self.assertIn("Metadata", staged)
            self.assertEqual(Path(argv[3]).read_bytes(), rules.read_bytes())
            return CompletedProcess(argv, 19)

        with patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "synthetic-key"}), \
                patch.object(cfn.shutil, "which", side_effect=executable), \
                patch.object(cfn.subprocess, "run", side_effect=mock_run) as run:
            code, report, payload = self.invoke("template", path, "--guard-rules", str(rules), "--validator-timeout", "3")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(code, 0)
        self.assertEqual(report["validation"], {"cfn-lint": "passed", "cfn-guard": "findings"})
        self.assertIn("cfn-guard_reported_findings", payload)
        self.assertNotIn("private-code-path", payload)

    def test_validator_timeout_and_unconfigured_guard_are_distinct(self):
        path = self.write({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})
        with patch.object(cfn.shutil, "which", return_value=str(self.root / "cfn-lint.exe")), \
                patch.object(cfn.subprocess, "run", side_effect=TimeoutExpired(["lint"], 1)):
            code, report, _ = self.invoke("template", path, "--validator-timeout", "1")
        self.assertEqual(code, 1)
        self.assertEqual(report["validation"], {"cfn-lint": "timed_out", "cfn-guard": "rules_not_supplied"})

    def test_nested_template_after_item_limit_cannot_trigger_linter(self):
        path = self.write({"Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket"},
            "Nested": {"Type": "AWS::CloudFormation::Stack", "Properties": {"TemplateURL": "/other.yaml"}},
        }})
        with patch.object(cfn.subprocess, "run") as run:
            code, report, _ = self.invoke("template", path, "--max-items", "1")
            run.assert_not_called()
        self.assertEqual(code, 1)
        self.assertEqual(report["validation"]["cfn-lint"], "nested_template_not_evaluated")

    def test_literal_variants_and_static_iam_statements_remain_visible(self):
        path = self.write({"Resources": {
            "Ingress": {"Type": "AWS::EC2::SecurityGroupIngress", "Properties": {
                "CidrIpv6": "0:0:0:0:0:0:0:0/0", "IpProtocol": -1,
            }},
            "Database": {"Type": "AWS::RDS::DBCluster", "Properties": {
                "PubliclyAccessible": "true", "StorageEncrypted": "false",
            }},
            "Policy": {"Type": "AWS::IAM::Policy", "Properties": {"PolicyDocument": {"Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": {"Fn::Sub": "arn:aws:s3:::${Bucket}/*"}},
            ]}}},
        }})
        with patch.object(cfn.shutil, "which", return_value=None):
            code, report, _ = self.invoke("template", path)
        self.assertEqual(code, 1)
        self.assertTrue({"internet_wide_ingress", "at_rest_encryption_explicitly_disabled",
                         "public_database_requested_network_access_unverified",
                         "wildcard_allow_review_effective_permissions"} <= {row["rule"] for row in report["findings"]})

    def test_change_set_distinguishes_actions_replacements_and_data_loss(self):
        path = self.write({"Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE", "Changes": [
            change(1, "Add"), change(2, "Modify", "True", PolicyAction="ReplaceAndDelete"),
            change(3, "Modify", "Conditional"), change(4, "Modify", "False"),
            change(5, "Modify"), change(6, "Remove", PolicyAction="Retain"), change(7, "Dynamic"),
        ], "StatusReason": "private-aws-error", "NextToken": "private-page-token"})
        code, report, payload = self.invoke("change-set", path)
        self.assertEqual(code, 1)
        self.assertEqual(report["summary"]["actions"], {"Add": 1, "Modify": 4, "Remove": 1, "Dynamic": 1})
        self.assertEqual(report["summary"]["replacements"], {"definite": 1, "conditional": 1, "none": 1, "unknown": 2})
        self.assertTrue(report["coverage"]["truncated"])
        self.assertIn("continuation_present", self.reasons(report))
        self.assertIn("old_state_deletion_indicated", report["evidence"]["changes"][1]["risk"])
        self.assertNotIn("old_state_deletion_indicated", report["evidence"]["changes"][5]["risk"])
        self.assertNotIn("private-", payload)
        self.assertNotIn("PrivateBucket", payload)

    def test_complete_and_failed_empty_change_sets_remain_distinct(self):
        for status, expected in (("CREATE_COMPLETE", 0), ("FAILED", 1)):
            with self.subTest(status=status):
                path = self.write({"Status": status, "ExecutionStatus": "AVAILABLE", "Changes": []})
                code, report, _ = self.invoke("change-set", path)
                self.assertEqual(code, expected)
                self.assertEqual(report["summary"]["change_set_status"], status)

    def test_import_and_metadata_sync_are_distinct_from_resource_replacement(self):
        path = self.write({"Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE", "IncludeNestedStacks": True,
                           "Changes": [change(1, "Import"), change(2, "SyncWithActual"),
                                       change(3, "Modify", "False", PolicyAction="ReplaceAndRetain")]})
        code, report, _ = self.invoke("change-set", path)
        self.assertEqual(code, 1)
        self.assertEqual(report["summary"]["actions"], {"Import": 1, "SyncWithActual": 1, "Modify": 1})
        self.assertEqual([row["replacement"] for row in report["evidence"]["changes"]],
                         ["not_applicable", "not_applicable", "unknown"])
        self.assertTrue({"nested_changes_not_reviewed", "conflicting_replacement_evidence"} <= self.reasons(report))

    def test_events_sort_redact_and_only_link_failure_from_matching_operation(self):
        events = [
            event(4, "UPDATE_ROLLBACK_COMPLETE"), event(2, "UPDATE_FAILED", ResourceStatusReason="Resource creation cancelled"),
            event(1, "UPDATE_FAILED", ResourceStatusReason="AccessDenied password=private-event-secret"),
            event(3, "UPDATE_ROLLBACK_IN_PROGRESS"), event(5, "UPDATE_ROLLBACK_FAILED", stack="second-private-stack"),
        ]
        path = self.write({"StackEvents": events, "NextToken": "private-page-token"})
        code, report, payload = self.invoke("events", path)
        self.assertEqual(code, 1)
        self.assertTrue(report["coverage"]["truncated"])
        self.assertEqual(report["summary"]["failures"], 3)
        self.assertEqual(report["summary"]["rollback_events"], 3)
        rows = report["evidence"]["events"]
        self.assertEqual([row["timestamp"] for row in rows], sorted(row["timestamp"] for row in rows))
        self.assertEqual(rows[0]["reason_category"], "authorization")
        self.assertEqual(rows[2]["earlier_failure_same_operation"], "e1")
        self.assertEqual(rows[3]["earlier_failure_same_operation"], "e1")
        self.assertNotIn("earlier_failure_same_operation", rows[4])
        self.assertNotIn("private-", payload)
        self.assertNotIn("PrivateResource", payload)

    def test_events_fail_closed_on_bad_data_and_report_item_limit(self):
        date = event(1, "CREATE_FAILED", time="2026-10-01T06:00:01")
        path = self.write({"StackEvents": [date, event(2, "CREATE_FAILED"), event(3, "ROLLBACK_COMPLETE")],
                           "collection": {"complete": False}})
        code, report, _ = self.invoke("events", path, "--max-items", "2")
        self.assertEqual(code, 1)
        self.assertEqual(report["summary"]["events_reviewed"], 1)
        self.assertTrue({"item_limit", "invalid_event", "upstream_coverage_incomplete"} <= self.reasons(report))

    def test_events_correlate_partial_operation_ids_and_distinguish_hook_warnings(self):
        path = self.write({"StackEvents": [
            event(1, "UPDATE_FAILED", ClientRequestToken="private-token"),
            event(2, None, HookStatus="HOOK_FAILED", HookFailureMode="WARN", HookStatusReason="private-reason"),
            event(3, "UPDATE_ROLLBACK_IN_PROGRESS", ClientRequestToken="private-token"),
            event(4, None, HookStatus="HOOK_FAILED", HookFailureMode="FAIL"),
        ]})
        data = json.loads(path.read_text(encoding="utf-8"))
        data["StackEvents"][2].pop("OperationId")
        code, report, payload = self.invoke("events", self.write(data))
        self.assertEqual(code, 0)
        rows = report["evidence"]["events"]
        self.assertEqual(rows[2]["earlier_failure_same_operation"], "e1")
        self.assertEqual(rows[0]["operation"], rows[2]["operation"])
        self.assertNotIn("failed", rows[1])
        self.assertTrue(rows[3]["failed"])
        self.assertEqual(report["summary"]["failures"], 2)
        self.assertEqual(report["summary"]["hook_failures"], 2)
        self.assertNotIn("private-", payload)

    def test_reused_token_does_not_link_different_operation_ids(self):
        first = event(1, "UPDATE_FAILED", ClientRequestToken="shared-token")
        second = event(2, "UPDATE_ROLLBACK_IN_PROGRESS", ClientRequestToken="shared-token")
        second["OperationId"] = "other-operation"
        third = event(3, "UPDATE_ROLLBACK_COMPLETE", ClientRequestToken="shared-token")
        third.pop("OperationId")
        _, report, _ = self.invoke("events", self.write({"StackEvents": [first, second, third]}))
        self.assertTrue(all("earlier_failure_same_operation" not in row for row in report["evidence"]["events"]))

    def test_malformed_oversized_and_pinned_files(self):
        for mode, data in (("events", '{"StackEvents":'), ("events", {"StackEvents": {}}),
                           ("change-set", {"Changes": "bad"}), ("template", '{"Resources":{},"Resources":{}}')):
            with self.subTest(mode=mode, data=data):
                code, report, _ = self.invoke(mode, self.write(data))
                self.assertEqual(code, 2)
                self.assertFalse(report["collection"]["complete"])
        path = self.write({"StackEvents": []})
        with patch.object(evidence, "MAX_INPUT_BYTES", 2):
            code, report, _ = self.invoke("events", path)
            self.assertEqual(code, 2)
            self.assertIn("source_exceeds_8MiB_limit", self.reasons(report))
        code, report, _ = self.invoke("events", path, "--sha256", "a" * 64)
        self.assertEqual(code, 2)
        self.assertIn("source_sha256_mismatch", self.reasons(report))

    def test_output_bound_keeps_counts_and_refuses_input_overwrite(self):
        path = self.write({"StackEvents": [event(i, "CREATE_FAILED") for i in range(50)]})
        code, report, payload = self.invoke("events", path, "--max-output-bytes", "4096")
        self.assertEqual(code, 1)
        self.assertLessEqual(len(payload.replace("\n", os.linesep).encode("utf-8")), 4096)
        self.assertEqual(report["summary"]["events_reviewed"], 50)
        self.assertGreater(report["coverage"]["omitted_rows"], 0)
        self.assertTrue(report["coverage"]["truncated"])
        before = path.read_bytes()
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.invoke("events", path, "--output", str(path))
        self.assertEqual(path.read_bytes(), before)

    def test_shared_reader_preserves_existing_slice_and_refuses_credential_paths(self):
        path = self.write({"StackEvents": []})
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        packet = evidence.read_evidence(path, "lines", ranges=[[1, 1]], sha256=digest)
        self.assertEqual(packet["source"]["sha256"], digest)
        self.assertEqual(packet["status"], "complete")
        code, report, _ = self.invoke("events", self.write({"StackEvents": []}, "credentials"))
        self.assertEqual(code, 2)
        self.assertIn("credential_file_not_read", self.reasons(report))

    def test_reviewer_rejects_symlink_and_legacy_reader_keeps_existing_behavior(self):
        path = self.write({"StackEvents": []})
        link = self.root / "link.json"
        try:
            link.symlink_to(path)
        except OSError:
            self.skipTest("symlink creation unavailable")
        code, report, _ = self.invoke("events", link)
        self.assertEqual(code, 2)
        self.assertIn("source_symlink_not_allowed", self.reasons(report))
        self.assertEqual(evidence.read_evidence(link, "lines", ranges=[[1, 1]])["status"], "complete")
