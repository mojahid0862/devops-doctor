#!/usr/bin/env python3
"""Collect bounded read-only GitLab pipeline/job evidence through glab only."""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from typing import Any

from doctor_common import emit_result, redact
from gitlab_mr_snapshot import (api_project, auth_failure, find_glab, page_limit,
    positive_int, result_blockers, run_glab, run_glab_tasks)


def tail_lines(text: str, max_lines: int) -> str:
    return "\n".join(redact(text).splitlines()[-max_lines:])


def classify_trace(trace: str, *, failed: bool = False) -> list[dict[str, Any]]:
    """Recognize actual error evidence only after job failure is established."""
    if not failed:
        return []
    rules = [
        ("dependency_install", "Dependency installation error", r"npm (?:err!|error)|(?:pnpm|yarn) (?:err!|error)|eresolve|could not resolve dependency|no matching distribution found|could not find a version that satisfies"),
        ("syntax_or_compile", "Syntax or compilation error", r"syntaxerror|parse error|error ts\d+|has already been declared|compilation failed"),
        ("test_failure", "Test assertion failure", r"assertionerror|\b[1-9]\d* failed(?:,|\s|$)|tests? failed|failed tests?"),
        ("docker_build", "Container build error", r"failed to solve|pull access denied|error (?:building|building image)|docker build.*(?:failed|error)"),
        ("registry_auth", "Registry authentication error", r"unauthorized: authentication required|denied: access forbidden|pull access denied|invalid credentials"),
        ("deploy_failure", "Deployment error", r"(?:deploy(?:ment)?|helm|kubectl).*(?:failed|error)|(?:failed|error).*(?:deploy(?:ment)?|helm|kubectl)"),
        ("aws_permission", "AWS permission or identity error", r"accessdenied|expiredtoken|not authorized to perform"),
        ("runner_or_capacity", "Runner or capacity error", r"runner system failure|no space left on device|out of memory|oomkilled"),
    ]
    findings = []
    for code, title, pattern in rules:
        evidence = [{"line": number, "text": redact(line)[:500]} for number, line in enumerate(trace.splitlines(), 1)
                    if re.search(pattern, line, re.IGNORECASE)]
        if evidence:
            findings.append({"code": code, "title": title, "evidence": evidence[:5]})
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


def build_root_cause_candidates(job_result: dict[str, Any], trace_tail: str,
                                jobs_summary: dict[str, Any]) -> list[dict[str, Any]]:
    job = job_result.get("data") if job_result.get("ok") else {}
    job = job if isinstance(job, dict) else {}
    failed = job.get("status") == "failed"
    candidates = [{"confidence": "medium", "category": item["code"], "reason": item["title"],
                   "evidence": item["evidence"]} for item in classify_trace(trace_tail, failed=failed)]
    if failed and job.get("failure_reason"):
        candidates.insert(0, {"confidence": "high", "category": "gitlab_failure_reason",
                              "reason": str(job["failure_reason"]),
                              "evidence": [f"job {job.get('id')} {job.get('name')}"]})
    if not candidates and jobs_summary.get("failed"):
        candidates.append({"confidence": "low", "category": "job_status",
                           "reason": "failed/canceled jobs require trace inspection; root cause unverified",
                           "evidence": jobs_summary["failed"][:3]})
    return candidates


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect bounded read-only GitLab pipeline evidence using glab only.")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pipeline-id")
    parser.add_argument("--job-id")
    parser.add_argument("--mr-iid")
    parser.add_argument("--trace-lines", type=positive_int, default=300)
    parser.add_argument("--max-workers", type=positive_int, default=8)
    parser.add_argument("--max-pages", type=page_limit, default=5)
    parser.add_argument("--output")
    args = parser.parse_args()
    if not (args.pipeline_id or args.job_id or args.mr_iid):
        parser.error("provide --pipeline-id, --job-id, or --mr-iid")
    return args


def main() -> int:
    args = parse_args()
    glab = find_glab()
    if not glab:
        print("glab not found; check PATH or DEVOPS_DOCTOR_GLAB.", file=sys.stderr)
        return 2
    auth = run_glab(glab, ["auth", "status"], timeout=30, parse_json=False)
    if not auth.get("ok"):
        return emit_result(auth_failure(auth, args.repo), args.output)
    snapshot: dict[str, Any] = {"generated_at": datetime.now(timezone.utc).isoformat(), "repo": args.repo,
                              "pipeline_id": args.pipeline_id, "job_id": args.job_id, "mr_iid": args.mr_iid, "auth": auth}
    tasks: dict[str, tuple[list[str], dict[str, Any]]] = {}
    if args.pipeline_id:
        tasks["pipeline"] = (["api", api_project(args.repo, "pipelines", args.pipeline_id)], {})
        tasks["pipeline_jobs"] = (["api", api_project(args.repo, "pipelines", args.pipeline_id, "jobs")], {"max_pages": args.max_pages})
    if args.job_id:
        tasks["job"] = (["api", api_project(args.repo, "jobs", args.job_id)], {})
        tasks["job_trace"] = (["api", api_project(args.repo, "jobs", args.job_id, "trace")], {"timeout": 90, "parse_json": False, "text_limit": 200000})
    if args.mr_iid:
        tasks["merge_request"] = (["api", api_project(args.repo, "merge_requests", args.mr_iid)], {})
    results = run_glab_tasks(glab, tasks, args.max_workers)
    trace = results.pop("job_trace", None)
    for key in ("pipeline", "job", "merge_request"):
        if key in results and results[key].get("ok") and not isinstance(results[key].get("data"), dict):
            results[key] = {**results[key], "ok": False, "error": f"invalid {key} response"}
    snapshot.update(results)
    if trace:
        text = str(trace.get("data") or "")
        lines = text.splitlines()
        snapshot["job_trace_tail"] = {**trace, "data": tail_lines(text, args.trace_lines),
                                      "truncated": bool(trace.get("truncated")) or len(lines) > args.trace_lines,
                                      "line_numbers_relative_to": "retained trace tail"}
    jobs_summary = summarize_jobs(snapshot.get("pipeline_jobs") or {})
    trace_text = str((snapshot.get("job_trace_tail") or {}).get("data") or "")
    job = snapshot.get("job") or {}
    candidates = build_root_cause_candidates(job, trace_text, jobs_summary)
    failed = isinstance(job.get("data"), dict) and job["data"].get("status") == "failed"
    result = {
        "summary": {"repo": args.repo, "pipeline_id": args.pipeline_id, "job_id": args.job_id,
                    "mr_iid": args.mr_iid, "failed_jobs": jobs_summary["failed"],
                    "status_counts": jobs_summary["status_counts"], "root_cause_candidates": candidates},
        "findings": [{"severity": "high" if item["status"] == "failed" else "info", "rule": "job_status", **item}
                     for item in jobs_summary["failed"]],
        "evidence": {"jobs_summary": jobs_summary, "trace_classification": classify_trace(trace_text, failed=failed)},
        "blockers": result_blockers(snapshot),
        "next_commands": [f"glab ci trace {args.job_id} --repo {args.repo}"] if args.job_id else [], "raw": snapshot,
    }
    return emit_result(result, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
