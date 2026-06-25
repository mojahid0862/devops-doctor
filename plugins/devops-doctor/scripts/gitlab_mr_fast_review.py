#!/usr/bin/env python3
"""Fast read-only GitLab MR score helper using glab only."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote


ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(private-token:\s*)[^\s]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(token|password|passwd|secret|key)(\s*[:=]\s*)([^\s\"']+)"), r"\1\2[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_ACCESS_KEY_ID]"),
]

KNOWN_GLAB_PATHS = [
    r"D:\apps\Git\cmd\glab.cmd",
    str(Path.home() / "AppData" / "Local" / "Programs" / "glab" / "glab.exe"),
]


def find_glab() -> str | None:
    found = shutil.which("glab")
    if found:
        return found
    return next((path for path in KNOWN_GLAB_PATHS if Path(path).exists()), None)


def redact(text: str) -> str:
    cleaned = ANSI_RE.sub("", text)
    for pattern, replacement in SECRET_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def truncate(text: str, max_chars: int = 50000) -> str:
    cleaned = redact(text)
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[: max_chars // 2] + "\n...[truncated]...\n" + cleaned[-max_chars // 2 :]


def run_glab(glab: str, args: list[str], *, timeout: int = 60, parse_json: bool = True) -> dict[str, Any]:
    command = [glab, *args]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "NO_COLOR": "1"},
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "command": " ".join(command)}

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    result: dict[str, Any] = {"ok": completed.returncode == 0, "command": " ".join(command)}
    if completed.returncode != 0:
        result["error"] = redact(stderr or stdout)[-2000:]
        return result

    if parse_json:
        try:
            result["data"] = json.loads(stdout) if stdout else None
        except json.JSONDecodeError:
            result["data"] = truncate(stdout, 8000)
    else:
        result["data"] = truncate(stdout)
    return result


def api_project(repo: str, *parts: str) -> str:
    return "/".join(["projects", quote(repo, safe=""), *[str(part).strip("/") for part in parts]])


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


def score_review(findings: list[dict[str, Any]], ci_statuses: list[str], mr_state: str | None) -> tuple[int, str, list[str]]:
    score = 100
    reasons: list[str] = []
    severities = [item.get("severity") for item in findings]
    for severity in severities:
        if severity == "critical":
            score -= 50
            score = min(score, 49)
        elif severity == "high":
            score -= 30
            score = min(score, 59)
        elif severity == "medium":
            score -= 15
        elif severity == "low":
            score -= 5

    if any(status in {"failed", "canceled"} for status in ci_statuses):
        score -= 25
        score = min(score, 59)
        reasons.append("required CI has failed/canceled status")
    elif not ci_statuses and mr_state != "merged":
        score -= 10
        reasons.append("CI status is unknown on an unmerged MR")

    score = max(score, 0)
    has_blocker = any(sev in {"critical", "high"} for sev in severities)
    verdict = "All good, can merge" if score >= 60 and not has_blocker else "Do not merge yet"
    if has_blocker:
        reasons.append("high or critical finding present")
    return score, verdict, reasons


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fast read-only GitLab MR score using glab only.")
    parser.add_argument("--repo", required=True, help="GitLab project path, for example group/project.")
    parser.add_argument("--mr-iid", required=True, help="Merge request IID.")
    parser.add_argument("--output", help="Write JSON result to this path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    glab = find_glab()
    if not glab:
        print("glab not found in PATH or known local install paths.", file=sys.stderr)
        return 2

    auth = run_glab(glab, ["auth", "status"], timeout=30, parse_json=False)
    mr_view = run_glab(glab, ["mr", "view", args.mr_iid, "--repo", args.repo, "--output", "json"], timeout=45)
    mr_api = run_glab(glab, ["api", api_project(args.repo, "merge_requests", args.mr_iid)], timeout=45)
    diff = run_glab(glab, ["mr", "diff", args.mr_iid, "--repo", args.repo], timeout=75, parse_json=False)

    mr_data = mr_api.get("data") if isinstance(mr_api.get("data"), dict) else {}
    if not mr_data and isinstance(mr_view.get("data"), dict):
        mr_data = mr_view["data"]
    sha = mr_data.get("sha") or mr_data.get("head_sha")
    merge_sha = mr_data.get("merge_commit_sha")
    mr_state = mr_data.get("state")

    pipelines = run_glab(glab, ["api", api_project(args.repo, "merge_requests", args.mr_iid, "pipelines")], timeout=45)
    statuses = run_glab(glab, ["api", api_project(args.repo, "repository", "commits", sha, "statuses")], timeout=45) if sha else {"ok": False, "error": "missing sha"}
    merge_statuses = None
    if not status_values(statuses) and merge_sha:
        merge_statuses = run_glab(glab, ["api", api_project(args.repo, "repository", "commits", merge_sha, "statuses")], timeout=45)

    diff_text = str(diff.get("data", "")) if diff.get("ok") else ""
    paths = changed_paths(diff_text)
    findings = scan_diff(diff_text)
    ci_values = status_values(statuses) or status_values(merge_statuses or {}) or [str(item.get("status", "")).lower() for item in pipelines.get("data", []) if isinstance(item, dict)]
    score, verdict, score_reasons = score_review(findings, ci_values, str(mr_state) if mr_state else None)

    blockers = []
    for name, result in {"auth": auth, "mr_view": mr_view, "mr_api": mr_api, "diff": diff, "pipelines": pipelines, "statuses": statuses}.items():
        if not result.get("ok"):
            blockers.append({"scope": name, "reason": result.get("error", "command failed")})

    result = {
        "summary": {
            "repo": args.repo,
            "mr_iid": args.mr_iid,
            "title": mr_data.get("title"),
            "state": mr_state,
            "source_branch": mr_data.get("source_branch"),
            "target_branch": mr_data.get("target_branch"),
            "sha": sha,
            "merge_commit_sha": merge_sha,
            "changed_files": len(paths),
            "score": score,
            "verdict": verdict,
            "score_reasons": score_reasons,
            "ci_statuses": ci_values,
        },
        "findings": findings,
        "evidence": {
            "changed_paths": paths,
            "risk_buckets": risk_buckets(paths),
            "pipeline_count": len(pipelines.get("data") or []) if pipelines.get("ok") else None,
        },
        "blockers": blockers,
        "next_commands": [
            f"glab mr view {args.mr_iid} --repo {args.repo} --output json",
            f"glab mr diff {args.mr_iid} --repo {args.repo}",
        ],
        "raw": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "glab_path": glab,
            "auth": auth,
            "mr_view": mr_view,
            "mr_api": mr_api,
            "pipelines": pipelines,
            "statuses": statuses,
            "merge_statuses": merge_statuses,
            "diff": {"ok": diff.get("ok"), "command": diff.get("command"), "error": diff.get("error"), "data": truncate(diff_text, 50000)},
        },
    }

    payload = json.dumps(result, indent=2, sort_keys=True, default=str)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
