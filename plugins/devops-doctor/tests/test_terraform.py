"""Offline regression cases for real Terraform show -json structures."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import terraform_plan_guard as guard


def plan(resource_type, before, after, *, actions=None, unknown=None):
    return {"format_version": "1.2", "terraform_version": "1.9.0", "resource_changes": [{"address": resource_type + ".example", "mode": "managed", "type": resource_type, "change": {"actions": actions or ["update"], "before": before, "after": after, "after_unknown": unknown or {}}}]}


def policy(effect="Allow", action="*", resource="*"):
    return {"policy": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": effect, "Action": action, "Resource": resource}]})}


class TerraformGuardTests(unittest.TestCase):
    def test_decodes_json_policy_and_flags_allow(self):
        result = guard.analyze_json(plan("aws_iam_policy", None, policy(), actions=["create"]))
        risk = next(f for f in result["findings"] if f["rule"] == "iam_wildcard")
        self.assertEqual(risk["change"], "introduced")
        self.assertEqual(risk["severity"], "high")
        self.assertEqual(risk["statements"][0]["scope"], "unrestricted")

    def test_deny_wildcard_does_not_grant_access(self):
        self.assertFalse(guard.contains_iam_wildcard(policy(effect="Deny")))
        result = guard.analyze_json(plan("aws_iam_policy", None, policy(effect="Deny")))
        self.assertNotIn("iam_wildcard", [f["rule"] for f in result["findings"]])

    def test_scoped_action_resource_patterns_are_not_admin_access(self):
        result = guard.analyze_json(plan("aws_iam_role_policy", None, policy(action=["s3:Get*"], resource=["arn:aws:s3:::reports/*"])))
        risk = next(f for f in result["findings"] if f["rule"] == "iam_wildcard")
        self.assertEqual(risk["severity"], "medium")
        self.assertEqual(risk["statements"][0]["scope"], "scoped_pattern")

    def test_trust_policy_wildcard_principal_and_condition(self):
        after = {"assume_role_policy": json.dumps({"Statement": {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}}})}
        risk = guard.iam_wildcards(after)[0]
        self.assertTrue(risk["conditions_present"])
        self.assertEqual(risk["patterns"], {"Principal": ["*"]})

    def test_egress_world_open_is_not_ingress(self):
        rule = {"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": ["::/0"]}
        for kind, value in [("aws_security_group", {"ingress": [], "egress": [rule]}), ("aws_security_group_rule", {**rule, "type": "egress"})]:
            with self.subTest(kind=kind):
                result = guard.analyze_json(plan(kind, None, value))
                self.assertFalse(any(f["rule"] == "public_network_ingress" for f in result["findings"]))

    def test_inline_and_standalone_ipv6_ingress(self):
        rule = {"protocol": "tcp", "from_port": 22, "to_port": 22, "ipv6_cidr_blocks": ["::/0"]}
        cases = [("aws_security_group", {"ingress": [rule]}), ("aws_security_group_rule", {**rule, "type": "ingress"}), ("aws_vpc_security_group_ingress_rule", {"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ipv6": "::/0"})]
        for kind, value in cases:
            with self.subTest(kind=kind):
                result = guard.analyze_json(plan(kind, None, value))
                self.assertTrue(any(f["rule"] == "public_network_ingress" for f in result["findings"]))

    def test_unchanged_risk_not_reported_as_new_regression(self):
        before = {"publicly_accessible": True, "deletion_protection": False, "tags": {"owner": "old"}}
        result = guard.analyze_json(plan("aws_db_instance", before, {**before, "tags": {"owner": "new"}}))
        self.assertEqual(result["summary"]["unchanged_risk_count"], 2)
        self.assertFalse(any(f["severity"] in {"high", "medium"} for f in result["findings"]))

    def test_protection_disabled_is_new_regression(self):
        result = guard.analyze_json(plan("aws_db_instance", {"deletion_protection": True}, {"deletion_protection": False}))
        self.assertEqual(result["findings"][0]["rule"], "rds_deletion_protection_disabled")
        self.assertEqual(result["findings"][0]["change"], "introduced")

    def test_remediation_is_planned_not_deployed(self):
        result = guard.analyze_json(plan("aws_db_instance", {"publicly_accessible": True}, {"publicly_accessible": False}))
        self.assertEqual(result["planned_resolved"][0]["change"], "planned_removal")
        self.assertFalse(any(f["rule"] == "rds_publicly_accessible" for f in result["findings"]))

    def test_unknown_after_policy_never_counts_as_resolved(self):
        result = guard.analyze_json(plan("aws_iam_policy", policy(), {"policy": None}, unknown={"policy": True}))
        self.assertEqual(result["planned_resolved"], [])
        self.assertEqual(result["unverified_removed"][0]["rule"], "iam_wildcard")
        self.assertEqual(result["findings"][0]["paths"], ["policy"])

    def test_iam_policy_order_noise_does_not_create_regression(self):
        a = {"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"], "Resource": ["arn:aws:s3:::reports/*", "arn:aws:s3:::reports"]}
        b = {"Effect": "Deny", "Action": "*", "Resource": "*"}
        before = {"policy": json.dumps({"Statement": [a, b]})}
        after = {"policy": json.dumps({"Statement": [b, {**a, "Action": list(reversed(a["Action"]))}]})}
        result = guard.analyze_json(plan("aws_iam_policy", before, after))
        self.assertEqual(result["summary"]["unchanged_risk_count"], 1)

    def test_relaxed_condition_is_detected_without_exposing_values(self):
        old_statement = {"Effect": "Allow", "Action": "s3:*", "Resource": "*", "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-private-example"}}}
        new_statement = {key: value for key, value in old_statement.items() if key != "Condition"}
        before = {"policy": json.dumps({"Statement": [old_statement]})}
        after = {"policy": json.dumps({"Statement": [new_statement]})}
        result = guard.analyze_json(plan("aws_iam_policy", before, after))
        risk = next(f for f in result["findings"] if f["rule"] == "iam_wildcard")
        self.assertEqual(risk["change"], "modified")
        self.assertNotIn("o-private-example", json.dumps(result))

    def test_replacement_preserves_lifecycle_order(self):
        for actions, expected in [(["create", "delete"], True), (["delete", "create"], False)]:
            result = guard.analyze_json(plan("aws_db_instance", {}, {}, actions=actions))
            replacement = next(f for f in result["findings"] if f["rule"] == "replacement")
            self.assertEqual(replacement["create_before_destroy"], expected)
            self.assertEqual(result["summary"]["replace"], 1)

    def test_text_review_does_not_echo_sensitive_source_lines(self):
        result = guard.analyze_text('password = "do-not-leak" # will be destroyed\negress = ["0.0.0.0/0"]')
        self.assertNotIn("do-not-leak", json.dumps(result))
        self.assertEqual(result["findings"][1]["severity"], "info")

    def test_restrict_public_buckets_flag_is_checked(self):
        result = guard.analyze_json(plan("aws_s3_bucket_public_access_block", {"restrict_public_buckets": True}, {"restrict_public_buckets": False}))
        self.assertEqual(result["findings"][0]["disabled"], ["restrict_public_buckets"])


if __name__ == "__main__":
    unittest.main()
