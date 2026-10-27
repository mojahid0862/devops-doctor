#!/usr/bin/env python3
"""Collect bounded, read-only GitLab MR evidence through glab only."""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from doctor_common import emit_result, redact, run_command


def find_glab() -> str | None:
    configured = os.environ.get("DEVOPS_DOCTOR_GLAB")
    # An invalid explicit override must not silently select another executable.
    return shutil.which(configured) if configured else shutil.which("glab")


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def page_limit(value: str) -> int:
    parsed = positive_int(value)
    if parsed > 20:
        raise argparse.ArgumentTypeError("must be <= 20")
    return parsed


def run_glab(glab: str, args: list[str], *, timeout: int = 60,
             parse_json: bool = True, text_limit: int | None = 200000) -> dict[str, Any]:
    return run_command([glab, *args], timeout=timeout, parse_json=parse_json, text_limit=text_limit)


def api_project(repo: str, *parts: str) -> str:
    return "/".join(["projects", quote(repo, safe=""), *[quote(str(part).strip("/"), safe="") for part in parts]])


def run_glab_pages(glab: str, endpoint: str, *, max_pages: int = 5,
                   per_page: int = 100) -> dict[str, Any]:
    """Bound API work and report incomplete evidence, including partial failures."""
    if not 1 <= max_pages <= 20 or not 1 <= per_page <= 100:
        raise ValueError("max_pages must be 1..20 and per_page 1..100")
    items: list[Any] = []
    commands: list[str] = []
    duration = 0
    for page in range(1, max_pages + 1):
        separator = "&" if "?" in endpoint else "?"
        result = run_glab(glab, ["api", f"{endpoint}{separator}per_page={per_page}&page={page}"])
        commands.append(result.get("command", ""))
        duration += result.get("duration_ms", 0)
        if not result.get("ok") or result.get("truncated") or not isinstance(result.get("data"), list):
            return {"ok": False, "error": result.get("error") or "incomplete or invalid list response",
                    "data": items, "pages": page, "complete": False, "truncated": bool(items) or bool(result.get("truncated")),
                    "commands": commands, "duration_ms": duration}
        batch = result["data"]
        if not all(isinstance(item, dict) for item in batch):
            return {"ok": False, "error": "invalid list item; expected an object", "data": items,
                    "pages": page, "complete": False, "truncated": bool(items),
                    "commands": commands, "duration_ms": duration}
        items.extend(batch)
        if len(batch) < per_page:
            return {"ok": True, "data": items, "pages": page, "complete": True,
                    "truncated": False, "commands": commands, "duration_ms": duration}
    return {"ok": True, "data": items, "pages": max_pages, "complete": False,
            "truncated": True, "error": "page limit reached; evidence may be incomplete",
            "commands": commands, "duration_ms": duration}


def run_glab_tasks(glab: str, tasks: dict[str, tuple[list[str], dict[str, Any]]],
                   max_workers: int) -> dict[str, dict[str, Any]]:
    def execute(command_args: list[str], options: dict[str, Any]) -> dict[str, Any]:
        options = dict(options)
        pages = options.pop("max_pages", None)
        if pages is not None:
            return run_glab_pages(glab, command_args[1], max_pages=pages, **options)
        return run_glab(glab, command_args, **options)
    results: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(tasks) or 1))) as executor:
        futures = {executor.submit(execute, command, options): key for key, (command, options) in tasks.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = {"ok": False, "error": redact(str(exc)), "command": "internal"}
    return results


def result_blockers(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    return [{"scope": key, "reason": value.get("error") or "incomplete evidence"}
            for key, value in snapshot.items() if isinstance(value, dict)
            and (value.get("ok") is False or value.get("truncated") or value.get("complete") is False)]


def changed_paths(changes_result: dict[str, Any]) -> list[str]:
    data = changes_result.get("data") or []
    changes = data.get("changes", []) if isinstance(data, dict) else data
    return [str(item.get("new_path") or item.get("old_path")) for item in changes
            if isinstance(item, dict) and (item.get("new_path") or item.get("old_path"))]


def validate_diffs(result: dict[str, Any]) -> dict[str, Any]:
    data = result.get("data")
    if isinstance(data, list) and any(isinstance(item, dict) and
                                   (item.get("collapsed") or item.get("too_large")) for item in data):
        return {**result, "complete": False, "truncated": True, "error": "GitLab omitted one or more file diffs"}
    return result


def summarize(snapshot: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    mr = (snapshot.get("merge_request") or {}).get("data") or {}
    if not isinstance(mr, dict):
        mr = {}
    paths = changed_paths(snapshot.get("changes") or {})
    blockers = result_blockers(snapshot)
    findings = [{"severity": "medium", "rule": "sensitive_path_changed", "path": path} for path in paths
                if any(item in path.lower() for item in (".gitlab-ci", "dockerfile", ".tf", "terraform", "iam", "security", ".env"))]
    pipelines = (snapshot.get("pipelines") or {}).get("data") or []
    return {"repo": snapshot.get("repo"), "mr_iid": snapshot.get("mr_iid"),
            "title": mr.get("title"), "state": mr.get("state"),
            "source_branch": mr.get("source_branch"), "target_branch": mr.get("target_branch"),
            "sha": mr.get("sha"), "changed_files": len(paths),
            "pipeline_count": len(pipelines) if isinstance(pipelines, list) else None}, findings, blockers


def auth_failure(auth: dict[str, Any], repo: str) -> dict[str, Any]:
    return {"summary": {"repo": repo, "verdict": "Blocked: GitLab authentication failed"},
            "findings": [], "evidence": {}, "blockers": [{"scope": "auth", "reason": auth.get("error") or "authentication failed"}],
            "next_commands": ["glab auth status"], "raw": {"auth": auth}}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect bounded read-only GitLab MR evidence using glab only.")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--mr-iid", required=True)
    parser.add_argument("--include-discussions", action="store_true")
    parser.add_argument("--max-workers", type=positive_int, default=8)
    parser.add_argument("--max-pages", type=page_limit, default=5, help="Maximum pages per list endpoint (1..20).")
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
    snapshot: dict[str, Any] = {"generated_at": datetime.now(timezone.utc).isoformat(),
                              "repo": args.repo, "mr_iid": args.mr_iid, "glab_path": glab, "auth": auth}
    tasks = {
        "merge_request": (["api", api_project(args.repo, "merge_requests", args.mr_iid)], {}),
        "changes": (["api", api_project(args.repo, "merge_requests", args.mr_iid, "diffs")], {"max_pages": args.max_pages}),
        "pipelines": (["api", api_project(args.repo, "merge_requests", args.mr_iid, "pipelines")], {"max_pages": args.max_pages}),
    }
    if args.include_discussions:
        tasks["discussions"] = (["api", api_project(args.repo, "merge_requests", args.mr_iid, "discussions")], {"max_pages": args.max_pages})
    snapshot.update(run_glab_tasks(glab, tasks, args.max_workers))
    snapshot["changes"] = validate_diffs(snapshot["changes"])
    mr_data = snapshot["merge_request"].get("data")
    if not isinstance(mr_data, dict):
        snapshot["merge_request"] = {**snapshot["merge_request"], "ok": False,
                                     "error": "invalid merge request response"}
    elif snapshot["changes"].get("ok"):
        expected = mr_data.get("changes_count")
        if expected is None or not str(expected).isdigit() or int(expected) != len(changed_paths(snapshot["changes"])):
            snapshot["changes"] = {**snapshot["changes"], "complete": False,
                                   "error": "cannot verify complete file list against MR changes_count"}
    summary, findings, blockers = summarize(snapshot)
    result = {"summary": summary, "findings": findings,
              "evidence": {"changed_paths": changed_paths(snapshot["changes"]), "included_discussions": args.include_discussions},
              "blockers": blockers, "next_commands": [f"glab mr diff {args.mr_iid} --repo {args.repo}"], "raw": snapshot}
    return emit_result(result, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
