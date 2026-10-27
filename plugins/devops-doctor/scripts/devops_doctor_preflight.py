#!/usr/bin/env python3
"""Check only requested DevOps Doctor tools; local checks never authenticate."""
from __future__ import annotations

import argparse
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from doctor_common import collect_status, emit_result, run_command


def run(command: list[str], timeout: int = 20) -> dict[str, Any]:
    return run_command(command, timeout=timeout, parse_json=False, text_limit=1200)


def run_json(command: list[str], timeout: int = 20) -> dict[str, Any]:
    # Parse the complete response before any display limit is applied.
    return run_command(command, timeout=timeout, parse_json=True)


def safe_aws_identity(identity: dict[str, Any]) -> dict[str, Any]:
    if not identity.get("ok"):
        return identity
    data = identity.get("data")
    if not isinstance(data, dict) or not data.get("Account") or not data.get("Arn"):
        return {**identity, "ok": False, "data": None, "error": "STS response lacks Account or Arn"}
    account = data["Account"]
    parts = str(data["Arn"]).split(":", 5)
    arn_shape = None
    if len(parts) == 6:
        resource_type = parts[5].split("/", 1)[0].split(":", 1)[0]
        arn_shape = ":".join([*parts[:5], f"{resource_type}/[redacted]"])
    return {key: value for key, value in identity.items() if key != "data"} | {
        "account": account, "arn_shape": arn_shape,
    }


def git_context() -> dict[str, Any]:
    git = shutil.which("git")
    if not git:
        return {"available": False, "inside_work_tree": False}
    inside = run([git, "rev-parse", "--is-inside-work-tree"], timeout=10)
    if not inside.get("ok"):
        return {"available": True, "inside_work_tree": False}
    commands = {
        "root": [git, "rev-parse", "--show-toplevel"],
        "branch": [git, "branch", "--show-current"],
        "status": [git, "status", "--short"],
        "remote": [git, "remote", "-v"],
    }
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = dict(zip(commands, pool.map(lambda cmd: run(cmd, 10), commands.values())))
    return {"available": True, "inside_work_tree": True, **results}


def glab_context() -> dict[str, Any]:
    glab = shutil.which("glab")
    if not glab:
        return {"available": False, "path": None, "ready": False, "blocker": "glab not found in PATH"}
    auth = run([glab, "auth", "status"], timeout=25)
    return {
        "available": True, "path": glab, "auth": auth, "ready": bool(auth.get("ok")),
        "blocker": None if auth.get("ok") else auth.get("error", "glab auth status failed"),
    }


def aws_context(profile: str | None = None, region: str | None = None) -> dict[str, Any]:
    aws = shutil.which("aws")
    if not aws:
        return {"available": False, "path": None, "ready": False, "blocker": "aws CLI not found in PATH"}
    command = [aws, "sts", "get-caller-identity", "--output", "json"]
    if profile:
        command += ["--profile", profile]
    if region:
        command += ["--region", region]
    identity = safe_aws_identity(run_json(command, timeout=25))
    return {
        "available": True, "path": aws, "identity": identity,
        "profile": profile, "region": region, "ready": bool(identity.get("ok")),
        "blocker": None if identity.get("ok") else identity.get("error", "aws sts get-caller-identity failed"),
    }


def optional_tool_context(name: str, command: list[str]) -> dict[str, Any]:
    path = shutil.which(name)
    if not path:
        return {"available": False, "path": None}
    return {"available": True, "path": path, "version": run([path, *command[1:]], timeout=15)}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=("gitlab", "aws", "local", "all"), default="local",
                        help="Probe only this scope. Default local performs no cloud/GitLab authentication.")
    parser.add_argument("--profile", help="AWS profile used only by aws/all scope.")
    parser.add_argument("--region", help="AWS region used only by aws/all scope.")
    parser.add_argument("--output", help="Write sanitized JSON to this path.")
    return parser.parse_args(argv)


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    probes = {}
    if args.scope in ("local", "all"):
        probes = {
            "git": git_context,
            "terraform": lambda: optional_tool_context("terraform", ["terraform", "version", "-json"]),
            "kubectl": lambda: optional_tool_context("kubectl", ["kubectl", "version", "--client=true", "-o", "json"]),
            "docker": lambda: optional_tool_context("docker", ["docker", "--version"]),
            "helm": lambda: optional_tool_context("helm", ["helm", "version", "--short"]),
        }
    if args.scope in ("gitlab", "all"):
        probes["glab"] = glab_context
    if args.scope in ("aws", "all"):
        probes["aws"] = lambda: aws_context(args.profile, args.region)
    with ThreadPoolExecutor(max_workers=min(4, len(probes))) as pool:
        futures = {key: pool.submit(probe) for key, probe in probes.items()}
        raw = {key: future.result() for key, future in futures.items()}
    blockers = [
        {"scope": "gitlab" if key == "glab" else key, "reason": value["blocker"]}
        for key, value in raw.items() if value.get("blocker")
    ]
    summary: dict[str, Any] = {"cwd": str(Path.cwd()), "scope": args.scope,
                               "generated_at": datetime.now(timezone.utc).isoformat()}
    for key, value in raw.items():
        if key in ("glab", "aws"):
            summary[f"{key}_ready"] = value["ready"]
        elif key == "git":
            summary["git_ready"] = value.get("inside_work_tree", False)
        else:
            summary[f"{key}_available"] = value.get("available", False)
    result = {"summary": summary, "findings": [], "evidence": {"probes_requested": list(probes)},
              "blockers": blockers, "next_commands": [], "raw": raw}
    result["status"] = collect_status(result)
    if blockers:
        result["status"] = "failed" if len(blockers) == len(probes) else "partial"
    return result


def main() -> int:
    args = parse_args()
    return emit_result(build_report(args), args.output)


if __name__ == "__main__":
    raise SystemExit(main())
