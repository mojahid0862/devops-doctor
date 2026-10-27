#!/usr/bin/env python3
"""Bounded read-only MR checks; heuristic scores never authorize merging."""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from typing import Any

from doctor_common import emit_result
from gitlab_mr_snapshot import (api_project, auth_failure, find_glab, page_limit,
    positive_int, result_blockers, run_glab, run_glab_tasks)


def changed_paths(diff_text: str) -> list[str]:
    paths: list[str] = []
    for line in diff_text.splitlines():
        if not line.startswith("diff --git "):
            continue
        match = re.search(r" b/(.+)$", line)
        if match:
            path = match.group(1).strip()
            if path not in paths:
                paths.append(path)
    return paths


def risk_buckets(paths: list[str]) -> dict[str, list[str]]:
    buckets = {
        "ci_cd": [],
        "docker": [],
        "infra": [],
        "aws": [],
        "security_sensitive": [],
        "mobile": [],
        "web": [],
        "tests": [],
        "docs": [],
    }
    for path in paths:
        lower = path.lower()
        add = lambda name: buckets[name].append(path) if path not in buckets[name] else None
        if ".gitlab-ci" in lower or lower.startswith(".gitlab/") or "jenkinsfile" in lower or "azure-pipelines" in lower:
            add("ci_cd")
        if "dockerfile" in lower or "docker-compose" in lower:
            add("docker")
        if lower.endswith((".tf", ".tfvars")) or "terraform" in lower or "helm" in lower or "chart.yaml" in lower or "/k8s/" in lower or "kubernetes" in lower:
            add("infra")
        if any(item in lower for item in ("iam", "securitygroup", "security-group", "vpc", "ecs", "rds", "s3", "cloudfront", "route53", "lambda", "elasticache", "cloudwatch")):
            add("aws")
        if any(item in lower for item in ("auth", "permission", "secret", ".env", "login", "token", "password", "jwt", "oauth", "cors", "nginx")):
            add("security_sensitive")
        if any(item in lower for item in ("android/", "ios/", "expo", "app.json", "eas.json", "react-native")):
            add("mobile")
        if any(item in lower for item in ("src/", "pages/", "components/", "next.config", "vite.config", "webpack", "public/")):
            add("web")
        if any(item in lower for item in ("test", "spec", "__tests__")):
            add("tests")
        if lower.endswith((".md", ".txt", ".adoc")):
            add("docs")
    return {key: value for key, value in buckets.items() if value}


def added_lines(diff_text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    new_line = 0
    for raw in diff_text.splitlines():
        if raw.startswith("@@"):
            match = re.search(r"\+(\d+)", raw)
            new_line = int(match.group(1)) - 1 if match else 0
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("+"):
            new_line += 1
            lines.append((new_line, raw[1:]))
        elif raw.startswith("-"):
            continue
        else:
            new_line += 1
    return lines


def scan_diff(diff_text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    rules = [
        ("high", "secret_like_value", re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}")),
        ("high", "redacted_sensitive_value", re.compile(r"\[REDACTED[^\]]*\]")),
        ("high", "aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
        ("high", "private_key_marker", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
        ("high", "open_network_cidr", re.compile(r"0\.0\.0\.0/0|::/0")),
        ("high", "privileged_container", re.compile(r"(?i)\bprivileged\s*:\s*true\b")),
        ("medium", "unsafe_html", re.compile(r"(?i)dangerouslySetInnerHTML|innerHTML\s*=")),
        ("medium", "eval_or_shell_exec", re.compile(r"(?i)\beval\s*\(|exec\s*\(|shell_exec|child_process")),
        ("medium", "docker_latest_tag", re.compile(r"(?i)^\s*FROM\s+\S+:latest\b")),
        ("low", "debug_console_log", re.compile(r"\bconsole\.(log|debug|warn|error)\s*\(")),
        ("low", "todo_marker", re.compile(r"(?i)\b(todo|fixme|hack)\b")),
    ]
    for line_no, line in added_lines(diff_text):
        for severity, rule, pattern in rules:
            if pattern.search(line):
                findings.append({"severity": severity, "rule": rule, "line": line_no})
    return findings


def status_values(result: dict[str, Any]) -> list[str]:
    data = result.get("data") if result.get("ok") else None
    if not isinstance(data, list):
        return []
    return [str(item.get("status", "")).lower() for item in data if isinstance(item, dict)]


def score_review(findings: list[dict[str, Any]], ci_statuses: list[str],
                 mr_state: str | None, *, evidence_complete: bool = True) -> tuple[int, str, list[str]]:
    score = max(0, 100 - sum({"critical": 50, "high": 30, "medium": 15, "low": 5}.get(item.get("severity"), 0) for item in findings))
    reasons: list[str] = []
    if not evidence_complete:
        reasons.append("required evidence is missing, failed, or incomplete")
    if not ci_statuses:
        reasons.append("CI is unverified for the current head SHA")
    elif any(status != "success" for status in ci_statuses):
        reasons.append("CI for the current head SHA is not entirely successful")
    if mr_state != "opened":
        reasons.append("merge request is not open")
    if any(item.get("severity") in {"critical", "high"} for item in findings):
        reasons.append("high or critical finding requires review")
    return score, "Blocked: review required" if reasons else "Evidence checks passed; review required", reasons


def ci_for_head(statuses: dict[str, Any], pipelines: dict[str, Any], sha: str | None) -> list[str]:
    """Only exact-head evidence counts; old pipelines cannot validate a new push."""
    if not sha:
        return []
    values: list[str] = []
    rows = statuses.get("data") if statuses.get("ok") else []
    if isinstance(rows, list):
        # The commit-status endpoint is explicitly scoped to this SHA. When a
        # response includes sha, reject a mismatch as well.
        latest: dict[str, dict[str, Any]] = {}
        for item in rows:
            if not isinstance(item, dict) or item.get("sha", sha) != sha:
                continue
            name = str(item.get("name") or item.get("context") or item.get("id"))
            old = latest.get(name)
            if old is None or int(item.get("id") or 0) > int(old.get("id") or 0):
                latest[name] = item
        values.extend(str(item.get("status") or "unknown").lower() for item in latest.values())
    rows = pipelines.get("data") if pipelines.get("ok") else []
    exact = [item for item in rows if isinstance(item, dict) and item.get("sha") == sha] if isinstance(rows, list) else []
    if exact:
        newest = max(exact, key=lambda item: int(item.get("id") or 0))
        values.append(str(newest.get("status") or "unknown").lower())
    return values


def revision_refs(data: Any, *, version: bool = False) -> dict[str, str] | None:
    """Require provenance for the source head and both target-side diff refs."""
    if not isinstance(data, dict):
        return None
    source = data if version else data.get("diff_refs")
    if not isinstance(source, dict):
        return None
    refs = {name + "_sha": source.get(name + ("_commit_sha" if version else "_sha"))
            for name in ("head", "base", "start")}
    if not all(isinstance(value, str) and value.strip() for value in refs.values()):
        return None
    if not version and data.get("sha") != refs["head_sha"]:
        return None
    return refs


def validate_diff_version(result: dict[str, Any], refs: dict[str, str], version_id: int) -> dict[str, Any]:
    if not result.get("ok"):
        return result
    data = result.get("data")
    reason = None
    if not isinstance(data, dict) or data.get("id") != version_id or revision_refs(data, version=True) != refs:
        reason = "diff version provenance does not match MR head/base/start refs"
    elif data.get("state") != "collected" or data.get("overflow"):
        reason = "GitLab diff version is not completely collected"
    else:
        diffs = data.get("diffs")
        if not isinstance(diffs, list) or not all(isinstance(item, dict) and
                isinstance(item.get("old_path"), str) and item["old_path"] and
                isinstance(item.get("new_path"), str) and item["new_path"] and
                isinstance(item.get("diff"), str) for item in diffs):
            reason = "invalid or missing file diffs in pinned version"
        elif any(item.get("collapsed") or item.get("too_large") for item in diffs):
            reason = "GitLab omitted one or more file diffs"
        elif any(not item["diff"].strip() and not item.get("renamed_file") and
                 not (item.get("a_mode") and item.get("b_mode") and item["a_mode"] != item["b_mode"])
                 for item in diffs):
            reason = "file diff content is missing from pinned version"
    return {**result, "complete": False, "error": reason} if reason else result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bounded read-only GitLab MR checks using glab only.")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--mr-iid", required=True)
    parser.add_argument("--max-workers", type=positive_int, default=4)
    parser.add_argument("--max-pages", type=page_limit, default=5)
    parser.add_argument("--output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    glab = find_glab()
    if not glab:
        print("glab not found; check PATH or DEVOPS_DOCTOR_GLAB.", file=sys.stderr)
        return 2
    auth = run_glab(glab, ["auth", "status"], timeout=30, parse_json=False)
    if not auth.get("ok"):
        return emit_result(auth_failure(auth, args.repo), args.output)
    tasks = {
        "merge_request": (["api", api_project(args.repo, "merge_requests", args.mr_iid)], {}),
        # Only the newest version is needed; a race or stale version fails closed.
        "latest_diff_version": (["api", api_project(args.repo, "merge_requests", args.mr_iid, "versions") + "?per_page=1"], {}),
        "pipelines": (["api", api_project(args.repo, "merge_requests", args.mr_iid, "pipelines")], {"max_pages": args.max_pages}),
    }
    evidence = run_glab_tasks(glab, tasks, args.max_workers)
    mr = evidence["merge_request"].get("data") or {}
    if not isinstance(mr, dict):
        evidence["merge_request"] = {**evidence["merge_request"], "ok": False, "error": "invalid merge request response"}
        mr = {}
    sha = mr.get("sha") or mr.get("head_sha")
    refs = revision_refs(mr)
    versions = evidence["latest_diff_version"]
    rows = versions.get("data") if versions.get("ok") else None
    version = rows[0] if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) else {}
    version_id = version.get("id")
    if not refs:
        evidence["merge_request"].update(complete=False, error=evidence["merge_request"].get("error") or "missing or inconsistent MR head/base/start refs")
    if (not refs or revision_refs(version, version=True) != refs or
            type(version_id) is not int or version_id < 1 or version.get("state") != "collected"):
        evidence["latest_diff_version"].update(complete=False, error=versions.get("error") or "cannot identify a complete diff version matching MR refs")
        version_id = None
    if refs and version_id:
        evidence.update(run_glab_tasks(glab, {
            "diff": (["api", api_project(args.repo, "merge_requests", args.mr_iid, "versions", str(version_id))], {"timeout": 75}),
            "statuses": (["api", api_project(args.repo, "repository", "commits", refs["head_sha"], "statuses")], {"max_pages": args.max_pages}),
        }, args.max_workers))
        evidence["diff"] = validate_diff_version(evidence["diff"], refs, version_id)
        # The immutable diff cannot race a push. Recheck once after collection to
        # avoid calling its CI evidence current when the MR has since changed.
        check = run_glab(glab, ["api", api_project(args.repo, "merge_requests", args.mr_iid)])
        if check.get("ok") and revision_refs(check.get("data")) != refs:
            check.update(complete=False, error="MR head/base/start refs changed or became unverifiable during collection")
        elif check.get("ok"):
            mr = check["data"]
        evidence["revision_check"] = check
    else:
        evidence["diff"] = {"ok": False, "error": "missing verified MR diff version"}
        evidence["statuses"] = {"ok": False, "error": "missing verified MR revision"}
    diff = evidence["diff"]
    diff_data = diff.get("data") if diff.get("ok") and diff.get("complete") is not False else None
    files = diff_data["diffs"] if isinstance(diff_data, dict) else []
    paths = list(dict.fromkeys(item["new_path"] for item in files))
    blockers = result_blockers(evidence)
    if not files:
        blockers.append({"scope": "diff", "reason": "no reviewable diff retrieved"})
    changes_count = mr.get("changes_count")
    if changes_count is None or not str(changes_count).isdigit() or int(changes_count) != len(paths):
        blockers.append({"scope": "diff", "reason": "cannot verify complete diff against MR changes_count"})
    if mr.get("draft") or mr.get("work_in_progress"):
        blockers.append({"scope": "merge_request", "reason": "merge request is a draft"})
    if mr.get("has_conflicts"):
        blockers.append({"scope": "merge_request", "reason": "merge request has conflicts"})
    findings = [{**finding, "path": item["new_path"]} for item in files for finding in scan_diff(item["diff"])]
    ci_values = ci_for_head(evidence["statuses"], evidence["pipelines"], str(sha) if sha else None)
    score, verdict, reasons = score_review(findings, ci_values, mr.get("state"), evidence_complete=not blockers)
    for reason in reasons:
        if reason != "required evidence is missing, failed, or incomplete":
            blockers.append({"scope": "review", "reason": reason})
    result = {
        "summary": {"repo": args.repo, "mr_iid": args.mr_iid, "title": mr.get("title"), "state": mr.get("state"),
                    "source_branch": mr.get("source_branch"), "target_branch": mr.get("target_branch"), "sha": sha,
                    "merge_commit_sha": mr.get("merge_commit_sha"), "changed_files": len(paths), "score": score,
                    "score_kind": "heuristic_only", "verdict": verdict, "score_reasons": reasons, "ci_statuses": ci_values},
        "findings": findings, "evidence": {"changed_paths": paths, "risk_buckets": risk_buckets(paths),
                                         "diff_refs": refs, "diff_version_id": version_id},
        "blockers": blockers, "next_commands": [f"glab mr view {args.mr_iid} --repo {args.repo}"],
        "raw": {"generated_at": datetime.now(timezone.utc).isoformat(), "auth": auth, **evidence},
    }
    return emit_result(result, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
