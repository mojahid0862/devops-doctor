#!/usr/bin/env python3
"""Review saved Terraform plans offline; findings describe planned changes only."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from doctor_common import emit_result, sanitize

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
NETWORK_TYPES = {"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}
RISK_TYPES = NETWORK_TYPES | {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_role", "aws_iam_user_policy", "aws_iam_group_policy", "aws_s3_bucket", "aws_s3_bucket_acl", "aws_s3_bucket_public_access_block", "aws_db_instance", "aws_rds_cluster"}


def walk(value: Any) -> list[Any]:
    values = [value]
    if isinstance(value, dict):
        for child in value.values():
            values.extend(walk(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(walk(child))
    return values


def contains_open_cidr(value: Any) -> bool:
    return any(item in OPEN_CIDRS for item in walk(value) if isinstance(item, str))


def strings(value: Any) -> list[str]:
    return sorted({item for item in walk(value) if isinstance(item, str)})


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def normalize_policy(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: normalize_policy(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return sorted([normalize_policy(item) for item in value], key=canonical)
    return value


def policy_statements(value: Any) -> list[dict[str, Any]]:
    """Decode Terraform JSON-string policy attributes before inspecting statements."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []
    result: list[dict[str, Any]] = []
    if isinstance(value, dict):
        statements = value.get("Statement")
        if isinstance(statements, dict):
            result.append(statements)
        elif isinstance(statements, list):
            result.extend(item for item in statements if isinstance(item, dict))
        for key, child in value.items():
            if key != "Statement":
                result.extend(policy_statements(child))
    elif isinstance(value, list):
        for child in value:
            result.extend(policy_statements(child))
    return result


def iam_wildcards(value: Any) -> list[dict[str, Any]]:
    findings = []
    for statement in policy_statements(value):
        # A Deny wildcard is not a broad permission grant. This is not a full
        # effective-permissions evaluator across all applicable policies.
        if statement.get("Effect") != "Allow":
            continue
        fields = {}
        for key in ("Action", "Resource", "Principal"):
            patterns = [item for item in strings(statement.get(key)) if "*" in item or "?" in item]
            if patterns:
                fields[key] = patterns
        if fields:
            broad = any(item == "*" for items in fields.values() for item in items)
            semantic = {key: statement[key] for key in ("Effect", "Action", "NotAction", "Resource", "NotResource", "Principal", "NotPrincipal", "Condition") if key in statement}
            fingerprint = hashlib.sha256(canonical(normalize_policy(semantic)).encode("utf-8")).hexdigest()
            findings.append({"patterns": fields, "scope": "unrestricted" if broad else "scoped_pattern", "conditions_present": bool(statement.get("Condition")), "statement_fingerprint": fingerprint})
    return [json.loads(item) for item in sorted({canonical(item) for item in findings})]


def contains_iam_wildcard(value: Any) -> bool:
    return bool(iam_wildcards(value))


def public_ingress(resource_type: str, value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    if resource_type == "aws_security_group":
        rules = value.get("ingress") or []
    elif resource_type == "aws_security_group_rule":
        rules = [value] if value.get("type") == "ingress" else []
    elif resource_type == "aws_vpc_security_group_ingress_rule":
        rules = [value]
    else:
        rules = []
    results = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        cidrs = sorted(set(strings({key: rule.get(key) for key in ("cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6")})) & OPEN_CIDRS)
        if cidrs:
            results.append({"cidrs": cidrs, "protocol": rule.get("ip_protocol", rule.get("protocol")), "from_port": rule.get("from_port"), "to_port": rule.get("to_port")})
    return [json.loads(item) for item in sorted({canonical(item) for item in results})]


def unknown_paths(value: Any, prefix: str = "") -> list[str]:
    if value is True:
        return [prefix or "*"]
    if isinstance(value, dict):
        return [path for key, item in value.items() for path in unknown_paths(item, f"{prefix}.{key}".strip("."))]
    if isinstance(value, list):
        return [path for index, item in enumerate(value) for path in unknown_paths(item, f"{prefix}[{index}]")]
    return []


def state_risks(resource_type: str, value: Any) -> dict[str, dict[str, Any]]:
    risks: dict[str, dict[str, Any]] = {}
    if not isinstance(value, dict):
        return risks
    ingress = public_ingress(resource_type, value)
    if ingress:
        risks["public_network_ingress"] = {"severity": "high", "exposures": ingress}
    if resource_type.startswith("aws_iam_"):
        patterns = iam_wildcards(value)
        if patterns:
            risks["iam_wildcard"] = {"severity": "high" if any(p["scope"] == "unrestricted" for p in patterns) else "medium", "statements": patterns, "assessment": "potential_broad_allow_not_effective_permissions"}
    if resource_type == "aws_s3_bucket_acl" and value.get("acl") in {"public-read", "public-read-write", "authenticated-read"}:
        risks["public_s3_acl"] = {"severity": "high", "acl": value["acl"]}
    if resource_type == "aws_s3_bucket_public_access_block":
        disabled = sorted(key for key in ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets") if value.get(key) is False)
        if disabled:
            risks["s3_public_access_block_disabled"] = {"severity": "medium", "disabled": disabled}
    if resource_type in {"aws_db_instance", "aws_rds_cluster"}:
        if value.get("deletion_protection") is False:
            risks["rds_deletion_protection_disabled"] = {"severity": "medium"}
        if value.get("publicly_accessible") is True:
            risks["rds_publicly_accessible"] = {"severity": "high"}
    return risks


def action_label(actions: list[str]) -> str:
    return "replace" if sorted(actions) == ["create", "delete"] else ",".join(actions)


def analyze_json(plan: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(plan, dict) or not ({"resource_changes", "format_version"} & plan.keys()) or not isinstance(plan.get("resource_changes", []), list):
        raise ValueError("Expected Terraform plan object with resource_changes list")
    findings: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []
    unchanged = 0
    counts = {"create": 0, "update": 0, "delete": 0, "replace": 0, "read": 0}
    for resource in plan.get("resource_changes", []):
        if not isinstance(resource, dict) or not isinstance(resource.get("change"), dict):
            raise ValueError("Each resource change must contain a change object")
        address = resource.get("address")
        resource_type = resource.get("type", "")
        if not isinstance(resource_type, str) or not isinstance(address, str):
            raise ValueError("Each resource requires string type and address")
        change = resource["change"]
        actions = change.get("actions", [])
        if not isinstance(actions, list) or not all(isinstance(item, str) for item in actions):
            raise ValueError("Resource actions must be a list of strings")
        before, after = change.get("before"), change.get("after")
        label = action_label(actions)
        if label in counts:
            counts[label] += 1
        for action in actions:
            if action in counts and label != action:
                counts[action] += 1
        base = {"address": address, "type": resource_type}
        initial_count = len(findings)
        if "delete" in actions:
            findings.append({**base, "severity": "high", "rule": "destructive_change", "actions": actions})
        if label == "replace":
            findings.append({**base, "severity": "high", "rule": "replacement", "actions": actions, "create_before_destroy": actions == ["create", "delete"]})
        unknown = sorted(unknown_paths(change.get("after_unknown", {})))
        if unknown:
            findings.append({**base, "severity": "info", "rule": "unknown_planned_values", "paths": unknown, "assessment": "manual_review_required"})
        old, new = state_risks(resource_type, before), state_risks(resource_type, after)
        for rule, risk in new.items():
            if old.get(rule) == risk:
                unchanged += 1
                continue
            findings.append({**base, **risk, "rule": rule, "change": "introduced" if rule not in old else "modified", "before": old.get(rule)})
        for rule in old.keys() - new.keys():
            item = {**base, **old[rule], "rule": rule}
            # Unknown planned attributes may explain an apparently absent risk.
            if unknown:
                unverified.append({**item, "change": "unverified_removal"})
            else:
                resolved.append({**item, "change": "planned_removal"})
        if resource_type in RISK_TYPES and before != after and len(findings) == initial_count:
            findings.append({**base, "severity": "info", "rule": "sensitive_resource_changed", "actions": actions})
    return {"summary": {**counts, "unchanged_risk_count": unchanged, "unknown_resource_count": sum(f["rule"] == "unknown_planned_values" for f in findings)}, "findings": findings, "planned_resolved": resolved, "unverified_removed": unverified, "limitations": ["Static planned-change review, not proof of deployed state or effective IAM permissions.", "Wildcard Allow patterns need context; scoped patterns and conditions may be intentional. Deny statements are not privilege grants.", "NotAction/NotResource, policy interactions, inherited permissions, custom ACL grants, and provider-specific rules need manual review.", "Modified risks require review; the tool does not prove whether a modified wildcard is broader or narrower."]}


def analyze_text(text: str) -> dict[str, Any]:
    findings = []
    for index, line in enumerate(text.splitlines(), 1):
        lower = line.lower()
        # Never echo the raw line: plan output may contain secrets.
        if "will be destroyed" in lower or "must be replaced" in lower:
            findings.append({"severity": "high", "rule": "destructive_text_plan", "line": index})
        if contains_open_cidr(re.findall(r"[0-9a-fA-F:.]+/\d+", line)):
            findings.append({"severity": "info", "rule": "public_cidr_text_requires_context", "line": index})
    return {"summary": {"text_lines": len(text.splitlines())}, "findings": findings, "limitations": ["Text input cannot reliably distinguish ingress/egress, before/after, or unknown values. Use saved plan JSON for risk classification."]}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Review a saved Terraform plan offline; no Terraform/cloud commands are run.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--plan-json", help="Path to terraform show -json output.")
    source.add_argument("--plan-text", help="Path to saved text plan; limited heuristic review.")
    parser.add_argument("--output", help="Write sanitized JSON to this path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.plan_json:
            result = analyze_json(json.loads(Path(args.plan_json).read_text(encoding="utf-8-sig")))
        else:
            result = analyze_text(Path(args.plan_text).read_text(encoding="utf-8-sig", errors="replace"))
    except (OSError, ValueError, TypeError) as exc:
        emit_result({"status": "failed", "summary": {"status": "error"}, "findings": [], "blockers": [{"scope": "plan", "reason": str(exc)}]}, args.output)
        return 2
    result.update({"evidence": {"plan_json": args.plan_json, "plan_text": args.plan_text}, "blockers": []})
    return emit_result(sanitize(result), args.output)


if __name__ == "__main__":
    raise SystemExit(main())
