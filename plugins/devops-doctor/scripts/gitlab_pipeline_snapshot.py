#!/usr/bin/env python3
"""Collect a read-only GitLab pipeline/job snapshot through glab only."""

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
    (re.compile(r"(?i)aws_secret_access_key\s*=\s*[^\s]+"), "aws_secret_access_key=[REDACTED]"),
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


def tail_lines(text: str, max_lines: int) -> str:
    lines = redact(text).splitlines()
    if len(lines) <= max_lines:
        return "\n".join(lines)
    return "\n".join(lines[-max_lines:])


def safe_command(command: list[str]) -> str:
    return " ".join(command)


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
        return {"ok": False, "error": "timeout", "command": safe_command(command)}

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    result: dict[str, Any] = {
        "ok": completed.returncode == 0,
        "command": safe_command(command),
    }
    if completed.returncode != 0:
        result["error"] = redact(stderr or stdout)[-2000:]
        return result

    if parse_json:
        try:
            result["data"] = json.loads(stdout) if stdout else None
        except json.JSONDecodeError:
            result["data"] = redact(stdout)[-4000:]
    else:
        result["data"] = redact(stdout)
    return result


def api_project(repo: str, *parts: str) -> str:
    return "/".join(["projects", quote(repo, safe=""), *[str(part).strip("/") for part in parts]])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect read-only GitLab pipeline evidence using glab only.")
    parser.add_argument("--repo", required=True, help="GitLab project path, for example group/project.")
    parser.add_argument("--pipeline-id", help="Pipeline ID to inspect.")
    parser.add_argument("--job-id", help="Failed job ID to inspect.")
    parser.add_argument("--mr-iid", help="Optional merge request IID for context.")
    parser.add_argument("--trace-lines", type=int, default=300, help="Tail this many redacted job trace lines.")
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
        "pipeline_id": args.pipeline_id,
        "job_id": args.job_id,
        "mr_iid": args.mr_iid,
        "glab_path": glab,
        "auth": run_glab(glab, ["auth", "status"], timeout=30, parse_json=False),
        "pipeline": None,
        "pipeline_jobs": None,
        "job": None,
        "job_trace_tail": None,
        "merge_request": None,
    }

    if args.pipeline_id:
        snapshot["pipeline"] = run_glab(glab, ["api", api_project(args.repo, "pipelines", args.pipeline_id)])
        snapshot["pipeline_jobs"] = run_glab(glab, ["api", api_project(args.repo, "pipelines", args.pipeline_id, "jobs")])

    if args.job_id:
        snapshot["job"] = run_glab(glab, ["api", api_project(args.repo, "jobs", args.job_id)])
        trace = run_glab(
            glab,
            ["api", api_project(args.repo, "jobs", args.job_id, "trace")],
            timeout=90,
            parse_json=False,
        )
        snapshot["job_trace_tail"] = {
            "ok": trace.get("ok"),
            "command": trace.get("command"),
            "error": trace.get("error"),
            "data": tail_lines(str(trace.get("data", "")), args.trace_lines) if trace.get("ok") else None,
        }

    if args.mr_iid:
        snapshot["merge_request"] = run_glab(glab, ["api", api_project(args.repo, "merge_requests", args.mr_iid)])

    payload = json.dumps(snapshot, indent=2, sort_keys=True, default=str)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
