#!/usr/bin/env python3
"""Summarize risky Terraform plan changes from plan JSON or text."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
RISK_TYPES = {
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
    "aws_security_group",
    "aws_security_group_rule",
    "aws_s3_bucket",
    "aws_s3_bucket_acl",
    "aws_s3_bucket_public_access_block",
    "aws_db_instance",
    "aws_rds_cluster",
}


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


def contains_iam_wildcard(value: Any) -> bool:
    text = json.dumps(value, sort_keys=True, default=str)
    patterns = [
        r'"Action"\s*:\s*"\*"',
        r'"Action"\s*:\s*\[\s*"\*"\s*\]',
        r'"Resource"\s*:\s*"\*"',
        r'"Resource"\s*:\s*\[\s*"\*"\s*\]',
        r'actions"\s*:\s*\[\s*"\*"\s*\]',
        r'resources"\s*:\s*\[\s*"\*"\s*\]',
    ]
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def action_label(actions: list[str]) -> str:
    if actions == ["delete", "create"]:
        return "replace"
    return ",".join(actions)


def analyze_json(plan: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    counts = {"create": 0, "update": 0, "delete": 0, "replace": 0, "read": 0}

    for change in plan.get("resource_changes", []):
        address = change.get("address")
        resource_type = change.get("type")
        actions = change.get("change", {}).get("actions", [])
        before = change.get("change", {}).get("before")
        after = change.get("change", {}).get("after")
        label = action_label(actions)
        if label in counts:
            counts[label] += 1
        for action in actions:
            if action in counts and label != action:
                counts[action] += 1

        if "delete" in actions:
            findings.append({"severity": "high", "rule": "destructive_change", "address": address, "type": resource_type, "actions": actions})
        if actions == ["delete", "create"]:
            findings.append({"severity": "high", "rule": "replacement", "address": address, "type": resource_type, "actions": actions})
        if resource_type in {"aws_security_group", "aws_security_group_rule"} and contains_open_cidr(after):
            findings.append({"severity": "high", "rule": "public_network_ingress_or_rule", "address": address, "type": resource_type})
        if resource_type and resource_type.startswith("aws_iam_") and contains_iam_wildcard(after):
            findings.append({"severity": "high", "rule": "iam_wildcard", "address": address, "type": resource_type})
        if resource_type == "aws_s3_bucket_acl" and json.dumps(after, default=str).lower().find("public") >= 0:
            findings.append({"severity": "high", "rule": "public_s3_acl", "address": address, "type": resource_type})
        if resource_type == "aws_s3_bucket_public_access_block" and isinstance(after, dict):
            disabled = [key for key, value in after.items() if key.startswith("block_") or key.startswith("ignore_") if value is False]
            if disabled:
                findings.append({"severity": "medium", "rule": "s3_public_access_block_disabled", "address": address, "disabled": disabled})
        if resource_type in {"aws_db_instance", "aws_rds_cluster"} and isinstance(after, dict):
            if after.get("deletion_protection") is False:
                findings.append({"severity": "medium", "rule": "rds_deletion_protection_disabled", "address": address, "type": resource_type})
            if after.get("publicly_accessible") is True:
                findings.append({"severity": "high", "rule": "rds_publicly_accessible", "address": address, "type": resource_type})
        if resource_type in RISK_TYPES and before != after and not any(item.get("address") == address for item in findings):
            findings.append({"severity": "info", "rule": "sensitive_resource_changed", "address": address, "type": resource_type, "actions": actions})

    return {"summary": counts, "findings": findings}


def analyze_text(text: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), 1):
        lower = line.lower()
        if "will be destroyed" in lower or "must be replaced" in lower:
            findings.append({"severity": "high", "rule": "destructive_text_plan", "line": idx, "detail": line.strip()})
        if "0.0.0.0/0" in line or "::/0" in line:
            findings.append({"severity": "high", "rule": "public_cidr_text_plan", "line": idx, "detail": line.strip()})
        if re.search(r'actions?\s*=\s*\[\s*"\*"\s*\]', line, re.IGNORECASE):
            findings.append({"severity": "high", "rule": "iam_wildcard_text_plan", "line": idx, "detail": line.strip()})
    return {"summary": {"text_lines": len(text.splitlines())}, "findings": findings}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Review Terraform plan JSON/text for risky changes.")
    parser.add_argument("--plan-json", help="Path to terraform show -json output.")
    parser.add_argument("--plan-text", help="Path to text terraform plan output.")
    parser.add_argument("--output", help="Write JSON result to this path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.plan_json and not args.plan_text:
        raise SystemExit("Provide --plan-json or --plan-text.")

    if args.plan_json:
        result = analyze_json(json.loads(Path(args.plan_json).read_text(encoding="utf-8")))
    else:
        result = analyze_text(Path(args.plan_text).read_text(encoding="utf-8", errors="replace"))

    payload = json.dumps(result, indent=2, sort_keys=True, default=str)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
