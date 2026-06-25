#!/usr/bin/env python3
"""Collect a read-only GitLab MR snapshot through glab only."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
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


def find_glab() -> str | None:
    found = shutil.which("glab")
    if found:
        return found
    for candidate in (
        r"D:\apps\Git\cmd\glab.cmd",
        str(Path.home() / "AppData" / "Local" / "Programs" / "glab" / "glab.exe"),
    ):
        if Path(candidate).exists():
            return candidate
    return None


def redact(text: str) -> str:
    cleaned = ANSI_RE.sub("", text)
    for pattern, replacement in SECRET_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def truncate(text: str, max_chars: int) -> str:
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
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env={**os.environ, "NO_COLOR": "1"},
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "command": " ".join(command)}

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    result: dict[str, Any] = {
        "ok": completed.returncode == 0,
        "command": " ".join(command),
    }
    if completed.returncode != 0:
        result["error"] = redact(stderr or stdout)[-2000:]
        return result

    if parse_json:
        try:
            result["data"] = json.loads(stdout) if stdout else None
        except json.JSONDecodeError:
            result["data"] = truncate(stdout, 6000)
    else:
        result["data"] = truncate(stdout, 12000)
    return result


def api_project(repo: str, *parts: str) -> str:
    return "/".join(["projects", quote(repo, safe=""), *[str(part).strip("/") for part in parts]])


def run_glab_tasks(glab: str, tasks: dict[str, tuple[list[str], dict[str, Any]]], max_workers: int) -> dict[str, dict[str, Any]]:
    workers = max(1, max_workers)
    with ThreadPoolExecutor(max_workers=min(workers, len(tasks) or 1)) as executor:
        futures = {
            key: executor.submit(run_glab, glab, command_args, **kwargs)
            for key, (command_args, kwargs) in tasks.items()
        }
        results: dict[str, dict[str, Any]] = {}
        for key, future in futures.items():
            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = {"ok": False, "error": redact(str(exc)), "command": "internal"}
        return results


def changed_paths(changes_result: dict[str, Any]) -> list[str]:
    data = changes_result.get("data") if changes_result.get("ok") else {}
    changes = data.get("changes", []) if isinstance(data, dict) else []
    return [item.get("new_path") or item.get("old_path") for item in changes if isinstance(item, dict)]


def summarize(snapshot: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    mr = snapshot.get("merge_request", {}).get("data") if isinstance(snapshot.get("merge_request"), dict) else {}
    paths = changed_paths(snapshot.get("changes") or {})
    blockers = [
        {"scope": key, "reason": value.get("error", "command failed")}
        for key, value in snapshot.items()
        if isinstance(value, dict) and value.get("ok") is False
    ]
    findings = []
    for path in paths:
        lower = str(path).lower()
        if any(item in lower for item in (".gitlab-ci", "dockerfile", ".tf", "terraform", "iam", "security", ".env")):
            findings.append({"severity": "medium", "rule": "sensitive_path_changed", "path": path})
    summary = {
        "repo": snapshot.get("repo"),
        "mr_iid": snapshot.get("mr_iid"),
        "title": mr.get("title") if isinstance(mr, dict) else None,
        "state": mr.get("state") if isinstance(mr, dict) else None,
        "source_branch": mr.get("source_branch") if isinstance(mr, dict) else None,
        "target_branch": mr.get("target_branch") if isinstance(mr, dict) else None,
        "sha": mr.get("sha") if isinstance(mr, dict) else None,
        "changed_files": len(paths),
        "pipeline_count": len(snapshot.get("pipelines", {}).get("data") or []) if isinstance(snapshot.get("pipelines"), dict) else None,
    }
    return summary, findings, blockers


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect read-only GitLab MR evidence using glab only.")
    parser.add_argument("--repo", required=True, help="GitLab project path, for example group/project.")
    parser.add_argument("--mr-iid", required=True, help="Merge request IID.")
    parser.add_argument("--include-discussions", action="store_true", help="Include MR discussions metadata.")
    parser.add_argument("--max-workers", type=int, default=8, help="Maximum concurrent glab read workers; lower if GitLab API throttles.")
    parser.add_argument("--output", help="Write JSON snapshot to this path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    glab = find_glab()
    if not glab:
        print("glab not found in PATH or known local install paths.", file=sys.stderr)
        return 2

    snapshot: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo": args.repo,
        "mr_iid": args.mr_iid,
        "glab_path": glab,
        "auth": run_glab(glab, ["auth", "status"], timeout=30, parse_json=False),
        "merge_request": None,
        "changes": None,
        "pipelines": None,
        "diff": None,
        "discussions": None,
    }
    tasks: dict[str, tuple[list[str], dict[str, Any]]] = {
        "merge_request": (["api", api_project(args.repo, "merge_requests", args.mr_iid)], {}),
        "changes": (["api", api_project(args.repo, "merge_requests", args.mr_iid, "changes")], {}),
        "pipelines": (["api", api_project(args.repo, "merge_requests", args.mr_iid, "pipelines")], {}),
        "diff": (["mr", "diff", args.mr_iid, "--repo", args.repo], {"timeout": 90, "parse_json": False}),
    }
    if args.include_discussions:
        tasks["discussions"] = (["api", api_project(args.repo, "merge_requests", args.mr_iid, "discussions")], {})
    snapshot.update(run_glab_tasks(glab, tasks, args.max_workers))

    summary, findings, blockers = summarize(snapshot)
    result = {
        "summary": summary,
        "findings": findings,
        "evidence": {
            "changed_paths": changed_paths(snapshot.get("changes") or {}),
            "included_discussions": bool(args.include_discussions),
        },
        "blockers": blockers,
        "next_commands": [
            f"glab mr view {args.mr_iid} --repo {args.repo} --output json",
            f"glab mr diff {args.mr_iid} --repo {args.repo}",
        ],
        "raw": snapshot,
    }

    payload = json.dumps(result, indent=2, sort_keys=True, default=str)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
