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
            encoding="utf-8",
            errors="replace",
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


def classify_trace(trace: str) -> list[dict[str, Any]]:
    lowered = trace.lower()
    rules = [
        ("dependency_install", "Dependency install failed", ["npm err!", "pnpm err!", "yarn error", "pip install", "could not resolve dependency", "eresolve"]),
        ("syntax_or_compile", "Syntax/compile error", ["syntaxerror", "parse error", "identifier", "has already been declared", "typescript", "babel"]),
        ("test_failure", "Test failure", ["failed tests", "test failed", "jest", "pytest", "rspec", "assertionerror"]),
        ("docker_build", "Docker build failed", ["docker build", "failed to solve", "no such file or directory", "pull access denied"]),
        ("registry_auth", "Registry authentication failed", ["unauthorized", "authentication required", "denied: access forbidden", "invalid credentials"]),
        ("deploy_failure", "Deploy command failed", ["deploy", "aws ecs update-service", "kubectl apply", "helm upgrade", "serverless deploy"]),
        ("aws_permission", "AWS permission or identity issue", ["accessdenied", "not authorized", "is not authorized to perform", "expiredtoken"]),
        ("runner_or_capacity", "Runner/capacity issue", ["runner system failure", "no space left on device", "killed", "out of memory", "oom"]),
    ]
    findings: list[dict[str, Any]] = []
    for code, title, needles in rules:
        matches = [needle for needle in needles if needle in lowered]
        if matches:
            findings.append({"code": code, "title": title, "matched": matches[:5]})
    return findings


def summarize_jobs(jobs_result: dict[str, Any]) -> dict[str, Any]:
    jobs = jobs_result.get("data") if jobs_result.get("ok") else []
    if not isinstance(jobs, list):
        return {"total": 0, "failed": [], "status_counts": {}}
    counts: dict[str, int] = {}
    failed = []
    for job in jobs:
        status = str(job.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1
        if status in {"failed", "canceled"}:
            failed.append(
                {
                    "id": job.get("id"),
                    "name": job.get("name"),
                    "stage": job.get("stage"),
                    "status": status,
                    "failure_reason": job.get("failure_reason"),
                    "web_url": job.get("web_url"),
                }
            )
    return {"total": len(jobs), "failed": failed, "status_counts": counts}


def build_root_cause_candidates(job_result: dict[str, Any], trace_tail: str, jobs_summary: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for item in classify_trace(trace_tail):
        candidates.append({"confidence": "medium", "category": item["code"], "reason": item["title"], "evidence": item["matched"]})
    job_data = job_result.get("data") if job_result.get("ok") else {}
    if isinstance(job_data, dict) and job_data.get("failure_reason"):
        candidates.insert(
            0,
            {
                "confidence": "high",
                "category": "gitlab_failure_reason",
                "reason": str(job_data.get("failure_reason")),
                "evidence": [f"job {job_data.get('id')} {job_data.get('name')}"],
            },
        )
    if not candidates and jobs_summary.get("failed"):
        candidates.append({"confidence": "low", "category": "failed_job", "reason": "pipeline has failed/canceled jobs; trace did not match known patterns", "evidence": jobs_summary["failed"][:3]})
    return candidates


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect read-only GitLab pipeline evidence using glab only.")
    parser.add_argument("--repo", required=True, help="GitLab project path, for example group/project.")
    parser.add_argument("--pipeline-id", help="Pipeline ID to inspect.")
    parser.add_argument("--job-id", help="Failed job ID to inspect.")
    parser.add_argument("--mr-iid", help="Optional merge request IID for context.")
    parser.add_argument("--trace-lines", type=int, default=300, help="Tail this many redacted job trace lines.")
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

    tasks: dict[str, tuple[list[str], dict[str, Any]]] = {}
    if args.pipeline_id:
        tasks["pipeline"] = (["api", api_project(args.repo, "pipelines", args.pipeline_id)], {})
        tasks["pipeline_jobs"] = (["api", api_project(args.repo, "pipelines", args.pipeline_id, "jobs")], {})

    if args.job_id:
        tasks["job"] = (["api", api_project(args.repo, "jobs", args.job_id)], {})
        tasks["job_trace"] = (["api", api_project(args.repo, "jobs", args.job_id, "trace")], {"timeout": 90, "parse_json": False})

    if args.mr_iid:
        tasks["merge_request"] = (["api", api_project(args.repo, "merge_requests", args.mr_iid)], {})

    task_results = run_glab_tasks(glab, tasks, args.max_workers)
    for key in ("pipeline", "pipeline_jobs", "job", "merge_request"):
        if key in task_results:
            snapshot[key] = task_results[key]

    trace = task_results.get("job_trace")
    if trace:
        snapshot["job_trace_tail"] = {
            "ok": trace.get("ok"),
            "command": trace.get("command"),
            "error": trace.get("error"),
            "data": tail_lines(str(trace.get("data", "")), args.trace_lines) if trace.get("ok") else None,
        }

    jobs_summary = summarize_jobs(snapshot["pipeline_jobs"] or {})
    trace_text = str((snapshot.get("job_trace_tail") or {}).get("data") or "")
    root_cause_candidates = build_root_cause_candidates(snapshot.get("job") or {}, trace_text, jobs_summary)
    blockers = [
        {"scope": key, "reason": value.get("error", "command failed")}
        for key, value in snapshot.items()
        if isinstance(value, dict) and value.get("ok") is False
    ]
    result = {
        "summary": {
            "repo": args.repo,
            "pipeline_id": args.pipeline_id,
            "job_id": args.job_id,
            "mr_iid": args.mr_iid,
            "failed_jobs": jobs_summary.get("failed", []),
            "status_counts": jobs_summary.get("status_counts", {}),
            "root_cause_candidates": root_cause_candidates,
        },
        "findings": [
            {"severity": "high", "rule": "failed_job", **job}
            for job in jobs_summary.get("failed", [])
        ],
        "evidence": {
            "jobs_summary": jobs_summary,
            "trace_classification": classify_trace(trace_text),
        },
        "blockers": blockers,
        "next_commands": [
            f"glab ci trace {args.job_id} --repo {args.repo}" if args.job_id else f"glab api {api_project(args.repo, 'pipelines', args.pipeline_id, 'jobs')}" if args.pipeline_id else "glab ci list",
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
