#!/usr/bin/env python3
"""Compare saved sanitized finding snapshots offline, with scope/coverage checks."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from doctor_common import emit_result, sanitize

NOISE_KEYS = {"generated_at", "collected_at", "observed_at", "last_seen_at", "first_seen_at", "timestamp"}


def canonical(value: Any, *, ignore_noise: bool = True) -> Any:
    if isinstance(value, dict):
        return {key: canonical(item, ignore_noise=ignore_noise) for key, item in sorted(value.items()) if not ignore_noise or key not in NOISE_KEYS}
    if isinstance(value, list):
        normalized = [canonical(item, ignore_noise=ignore_noise) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def scope_of(snapshot: dict[str, Any]) -> dict[str, Any]:
    explicit = snapshot.get("scope")
    if explicit is not None:
        if not isinstance(explicit, dict):
            raise ValueError("scope must be an object")
        scope = dict(explicit)
    else:
        summary = snapshot.get("summary", {})
        evidence = snapshot.get("evidence", {})
        identity = evidence.get("identity", {})
        data = identity.get("data", {}) if isinstance(identity, dict) and identity.get("ok") is True else {}
        scope = {"account_id": data.get("Account"), "region": summary.get("region"), "filters": evidence.get("filters"), "collector": "aws_stack_snapshot" if "services_collected" in summary else None}
        if "services_collected" in summary:
            scope["services"] = summary["services_collected"]
    for key in ("account_id", "region", "collector"):
        if not isinstance(scope.get(key), str) or not scope[key].strip() or "redact" in scope[key].lower():
            raise ValueError(f"Snapshot requires a verified scope.{key}")
    if not isinstance(scope.get("filters"), dict):
        raise ValueError("Snapshot requires explicit scope.filters ({} for unfiltered)")
    return canonical(scope, ignore_noise=False)


def has_incomplete_marker(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if (key in {"ok", "complete"} and item is False) or (key in {"truncated", "IsTruncated", "partial", "incomplete"} and item is True):
                return True
            if key == "status" and item in ("failed", "partial", "error", "blocked"):
                return True
            if key in {"NextToken", "nextToken", "NextMarker", "Marker", "next_token", "NextPageToken", "NextContinuationToken"} and item:
                return True
            if has_incomplete_marker(item):
                return True
    elif isinstance(value, list):
        return any(has_incomplete_marker(item) for item in value)
    return False


def completeness(snapshot: dict[str, Any]) -> tuple[bool, list[str]]:
    collection = snapshot.get("collection", snapshot.get("evidence", {}).get("collection", {}))
    reasons = []
    if not isinstance(collection, dict) or collection.get("complete") is not True:
        reasons.append("collection.complete is not explicitly true")
    if snapshot.get("blockers"):
        reasons.append("snapshot contains collection blockers")
    if has_incomplete_marker(snapshot):
        reasons.append("snapshot contains failed, partial, truncated, or unconsumed pagination results")
    return not reasons, reasons


def index_findings(snapshot: dict[str, Any]) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    findings = snapshot.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Snapshot findings must be a list")
    result = {}
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Each finding must be an object")
        resource = finding.get("resource", finding.get("address"))
        rule = finding.get("rule")
        if not isinstance(resource, str) or not resource or not isinstance(rule, str) or not rule:
            raise ValueError("Each finding requires a stable resource/address and rule string")
        identity = (str(finding.get("service", "")), str(finding.get("type", "")), resource, rule)
        normalized = canonical(finding)
        if identity in result and result[identity] != normalized:
            raise ValueError("Conflicting duplicate finding identity; aggregate findings per resource/rule before comparison")
        result[identity] = normalized
    return result


def compare_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("Snapshots must be JSON objects")
    old_scope, new_scope = scope_of(before), scope_of(after)
    if old_scope != new_scope:
        changed = sorted(key for key in old_scope.keys() | new_scope.keys() if old_scope.get(key) != new_scope.get(key))
        raise ValueError("Incompatible snapshot scope: " + ", ".join(changed))
    old, new = index_findings(before), index_findings(after)
    before_complete, before_reasons = completeness(before)
    after_complete, after_reasons = completeness(after)
    complete = before_complete and after_complete
    added = [new[key] for key in sorted(new.keys() - old.keys())]
    removed = [old[key] for key in sorted(old.keys() - new.keys())]
    changed = [{"identity": {"service": key[0], "type": key[1], "resource": key[2], "rule": key[3]}, "before": old[key], "after": new[key]} for key in sorted(old.keys() & new.keys()) if old[key] != new[key]]
    unchanged = sum(old[key] == new[key] for key in old.keys() & new.keys())
    return {"summary": {"status": "complete" if complete else "partial", "added": len(added), "changed": len(changed), "resolved": len(removed) if complete else 0, "unverified_removed": 0 if complete else len(removed), "unchanged": unchanged}, "scope": old_scope, "added": added, "changed": changed, "resolved": removed if complete else [], "unverified_removed": [] if complete else removed, "coverage": {"before_complete": before_complete, "after_complete": after_complete, "before_reasons": before_reasons, "after_reasons": after_reasons}, "limitations": ["Compares recorded findings only, not full infrastructure configuration, inventory, or effective security posture.", "Added means newly observed in these files; an incomplete baseline does not prove when an issue began.", "Resolved means absent from a complete comparable finding set, not independently validated remediation.", "Observation timestamps and list order are ignored; event timestamps and scope filters remain significant.", "Matching collector names do not prove matching rule versions; use the same collector/ruleset version for both snapshots."]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare two saved sanitized finding snapshots without network access.")
    parser.add_argument("--before", required=True, help="Baseline JSON snapshot.")
    parser.add_argument("--after", required=True, help="Current JSON snapshot with matching scope.")
    parser.add_argument("--output", help="Write sanitized comparison JSON.")
    args = parser.parse_args()
    try:
        before = json.loads(Path(args.before).read_text(encoding="utf-8-sig"))
        after = json.loads(Path(args.after).read_text(encoding="utf-8-sig"))
        result = compare_snapshots(before, after)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        emit_result({"status": "failed", "summary": {"status": "error"}, "blockers": [{"scope": "snapshot_diff", "reason": str(exc)}]}, args.output)
        return 2
    result["status"] = result["summary"]["status"]
    return emit_result(sanitize(result), args.output)


if __name__ == "__main__":
    raise SystemExit(main())
