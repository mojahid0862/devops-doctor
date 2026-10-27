"""Offline coverage and identity regression tests for finding comparisons."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import snapshot_diff as diff


def finding(resource="db-a", rule="publicly_accessible", **extra):
    return {"service": "rds", "resource": resource, "rule": rule, "severity": "high", **extra}


def snapshot(findings=None, *, complete=True):
    return {"scope": {"account_id": "111122223333", "region": "ap-south-1", "collector": "aws_stack_snapshot", "services": ["rds"], "filters": {"db": None, "since": "2h"}}, "collection": {"complete": complete}, "findings": findings or [], "blockers": []}


class SnapshotDiffTests(unittest.TestCase):
    def test_added_resolved_and_changed_keep_stable_identity(self):
        old = snapshot([finding("db-a"), finding("db-b", severity="medium")])
        new = snapshot([finding("db-b", severity="high"), finding("db-c")])
        result = diff.compare_snapshots(old, new)
        self.assertEqual(result["summary"], {"status": "complete", "added": 1, "changed": 1, "resolved": 1, "unverified_removed": 0, "unchanged": 0})
        self.assertEqual(result["changed"][0]["identity"]["resource"], "db-b")
        self.assertEqual(result["resolved"][0]["resource"], "db-a")

    def test_order_and_observation_timestamps_do_not_change_findings(self):
        old = snapshot([finding("db-a", cidrs=["::/0", "0.0.0.0/0"], observed_at="2026-01-01T00:00:00Z"), finding("db-b")])
        new = snapshot([finding("db-b"), finding("db-a", cidrs=["0.0.0.0/0", "::/0"], observed_at="2026-01-02T00:00:00Z")])
        self.assertEqual(diff.compare_snapshots(old, new)["summary"]["unchanged"], 2)

    def test_event_timestamps_remain_meaningful(self):
        old = snapshot([finding(event_time="2026-01-01T00:00:00Z")])
        new = snapshot([finding(event_time="2026-01-02T00:00:00Z")])
        self.assertEqual(diff.compare_snapshots(old, new)["summary"]["changed"], 1)

    def test_account_region_filters_collector_mismatch_are_errors(self):
        for key, value in [("account_id", "999988887777"), ("region", "us-east-1"), ("filters", {"db": "db-other"}), ("collector", "another_collector"), ("services", ["ecs"])]:
            with self.subTest(key=key):
                old, new = snapshot(), snapshot()
                new["scope"][key] = value
                with self.assertRaisesRegex(ValueError, "Incompatible snapshot scope"):
                    diff.compare_snapshots(old, new)

    def test_same_missing_scope_does_not_count_as_verified_match(self):
        with self.assertRaisesRegex(ValueError, "verified scope.account_id"):
            diff.compare_snapshots({"findings": []}, {"findings": []})

    def test_explicit_empty_filter_scope_is_required(self):
        old = snapshot()
        del old["scope"]["filters"]
        with self.assertRaisesRegex(ValueError, "scope.filters"):
            diff.compare_snapshots(old, old)

    def test_either_incomplete_snapshot_prevents_resolved_claim(self):
        for before_complete, after_complete in [(False, True), (True, False), (False, False)]:
            result = diff.compare_snapshots(snapshot([finding()], complete=before_complete), snapshot(complete=after_complete))
            self.assertEqual(result["resolved"], [])
            self.assertEqual(len(result["unverified_removed"]), 1)
            self.assertEqual(result["summary"]["status"], "partial")

    def test_missing_completeness_is_not_success(self):
        old, new = snapshot([finding()]), snapshot()
        del new["collection"]
        result = diff.compare_snapshots(old, new)
        self.assertEqual(result["resolved"], [])

    def test_failure_pagination_and_truncation_override_complete(self):
        evidence_cases = [{"ok": False}, {"data": {"NextToken": "opaque-page"}}, {"truncated": True}, {"complete": False}]
        for evidence in evidence_cases:
            with self.subTest(evidence=evidence):
                new = snapshot()
                new["raw"] = {"query": evidence}
                result = diff.compare_snapshots(snapshot([finding()]), new)
                self.assertEqual(result["resolved"], [])

    def test_blockers_override_complete(self):
        new = snapshot()
        new["blockers"] = [{"scope": "rds", "reason": "AccessDenied"}]
        self.assertEqual(diff.compare_snapshots(snapshot([finding()]), new)["resolved"], [])

    def test_conflicting_duplicate_identity_is_rejected(self):
        bad = snapshot([finding(severity="medium"), finding(severity="high")])
        with self.assertRaisesRegex(ValueError, "duplicate finding identity"):
            diff.compare_snapshots(bad, snapshot())

    def test_identical_duplicate_identity_is_deduplicated(self):
        result = diff.compare_snapshots(snapshot([finding(), finding()]), snapshot([finding()]))
        self.assertEqual(result["summary"]["unchanged"], 1)

    def test_missing_resource_identity_is_rejected(self):
        bad = snapshot([{"rule": "publicly_accessible", "severity": "high"}])
        with self.assertRaisesRegex(ValueError, "stable resource/address"):
            diff.compare_snapshots(bad, snapshot())

    def test_terraform_address_is_supported(self):
        item = {"address": "aws_db_instance.main", "type": "aws_db_instance", "rule": "rds_publicly_accessible"}
        result = diff.compare_snapshots(snapshot(), snapshot([item]))
        self.assertEqual(result["summary"]["added"], 1)

    def test_legacy_stack_identity_inference_is_conservative(self):
        legacy = {"summary": {"region": "ap-south-1", "services_collected": ["rds"]}, "evidence": {"identity": {"ok": True, "data": {"Account": "111122223333"}}, "filters": {"db": None}}, "findings": [finding()], "blockers": []}
        after = copy.deepcopy(legacy)
        after["findings"] = []
        result = diff.compare_snapshots(legacy, after)
        self.assertEqual(result["resolved"], [])
        self.assertEqual(result["summary"]["unverified_removed"], 1)

    def test_cli_returns_json_error_for_scope_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            before = Path(directory) / "before.json"
            after = Path(directory) / "after.json"
            before.write_text(json.dumps(snapshot()), encoding="utf-8")
            changed = snapshot()
            changed["scope"]["region"] = "us-west-2"
            after.write_text(json.dumps(changed), encoding="utf-8")
            result = subprocess.run([sys.executable, str(SCRIPTS / "snapshot_diff.py"), "--before", str(before), "--after", str(after)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(json.loads(result.stdout)["summary"]["status"], "error")

    def test_cli_partial_and_complete_exit_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            before, after = Path(directory) / "before.json", Path(directory) / "after.json"
            before.write_text(json.dumps(snapshot([finding()])), encoding="utf-8")
            for complete, exit_code in [(True, 0), (False, 1)]:
                with self.subTest(complete=complete):
                    after.write_text(json.dumps(snapshot(complete=complete)), encoding="utf-8")
                    result = subprocess.run([sys.executable, str(SCRIPTS / "snapshot_diff.py"), "--before", str(before), "--after", str(after)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, exit_code, result.stderr)
                    payload = json.loads(result.stdout)
                    self.assertEqual(payload["collection"]["complete"], complete)
                    self.assertEqual(len(payload["resolved"]), 1 if complete else 0)


if __name__ == "__main__":
    unittest.main()
