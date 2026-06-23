#!/usr/bin/env python3
"""Read-only local readiness check for DevOps Doctor."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


KNOWN_GLAB_PATHS = [
    r"D:\apps\Git\cmd\glab.cmd",
    str(Path.home() / "AppData" / "Local" / "Programs" / "glab" / "glab.exe"),
]


def which_with_known(name: str, known_paths: list[str] | None = None) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for candidate in known_paths or []:
        if Path(candidate).exists():
            return candidate
    return None


def run(command: list[str], timeout: int = 20) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "command": " ".join(command)}
    except OSError as exc:
        return {"ok": False, "error": str(exc), "command": " ".join(command)}

    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "command": " ".join(command),
        "stdout_tail": completed.stdout.strip()[-1200:],
        "stderr_tail": completed.stderr.strip()[-1200:],
    }


def run_json(command: list[str], timeout: int = 20) -> dict[str, Any]:
    result = run(command, timeout)
    if not result.get("ok"):
        return result
    try:
        result["json"] = json.loads(result.get("stdout_tail") or "{}")
    except json.JSONDecodeError:
        result["json"] = None
    result.pop("stdout_tail", None)
    return result


def safe_aws_identity(identity: dict[str, Any]) -> dict[str, Any]:
    if not identity.get("ok"):
        return identity
    data = identity.get("json") or {}
    account = data.get("Account")
    arn = data.get("Arn", "")
    arn_shape = None
    if isinstance(arn, str) and ":" in arn:
        parts = arn.split(":", 5)
        if len(parts) == 6:
            resource_type = parts[5].split("/", 1)[0].split(":", 1)[0]
            arn_shape = ":".join([parts[0], parts[1], parts[2], parts[3], account or parts[4], f"{resource_type}/[redacted]"])
    return {
        "ok": True,
        "returncode": identity.get("returncode"),
        "command": identity.get("command"),
        "account": account,
        "arn_shape": arn_shape,
        "stderr_tail": identity.get("stderr_tail", ""),
    }


def command_status(name: str, known_paths: list[str] | None = None) -> dict[str, Any]:
    path = which_with_known(name, known_paths)
    return {"available": bool(path), "path": path}


def git_context() -> dict[str, Any]:
    git = shutil.which("git")
    if not git:
        return {"available": False}
    inside = run([git, "rev-parse", "--is-inside-work-tree"], timeout=10)
    if not inside["ok"]:
        return {"available": True, "inside_work_tree": False}
    return {
        "available": True,
        "inside_work_tree": True,
        "root": run([git, "rev-parse", "--show-toplevel"], timeout=10),
        "branch": run([git, "branch", "--show-current"], timeout=10),
        "status": run([git, "status", "--short"], timeout=10),
        "remote": run([git, "remote", "-v"], timeout=10),
    }


def glab_context() -> dict[str, Any]:
    glab = which_with_known("glab", KNOWN_GLAB_PATHS)
    if not glab:
        return {"available": False, "path": None, "ready": False, "blocker": "glab not found"}
    auth = run([glab, "auth", "status"], timeout=25)
    return {
        "available": True,
        "path": glab,
        "auth": auth,
        "ready": auth["ok"],
        "blocker": None if auth["ok"] else "glab auth status failed",
    }


def aws_context() -> dict[str, Any]:
    aws = shutil.which("aws")
    if not aws:
        return {"available": False, "path": None, "ready": False, "blocker": "aws CLI not found"}
    identity = safe_aws_identity(run_json([aws, "sts", "get-caller-identity", "--output", "json"], timeout=25))
    profiles = run([aws, "configure", "list-profiles"], timeout=15)
    return {
        "available": True,
        "path": aws,
        "identity": identity,
        "profiles": profiles,
        "region_env": os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
        "profile_env": os.environ.get("AWS_PROFILE"),
        "ready": identity["ok"],
        "blocker": None if identity["ok"] else "aws sts get-caller-identity failed",
    }


def optional_tool_context(name: str, command: list[str]) -> dict[str, Any]:
    path = shutil.which(name)
    if not path:
        return {"available": False, "path": None}
    return {"available": True, "path": path, "version": run(command, timeout=15)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check local DevOps Doctor tool readiness without exposing secrets.")
    parser.add_argument("--output", help="Write JSON result to this path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cwd": str(Path.cwd()),
        "git": git_context(),
        "glab": glab_context(),
        "aws": aws_context(),
        "terraform": optional_tool_context("terraform", ["terraform", "version", "-json"]),
        "kubectl": optional_tool_context("kubectl", ["kubectl", "version", "--client=true", "-o", "json"]),
        "docker": optional_tool_context("docker", ["docker", "version", "--format", "{{json .Client}}"]),
        "helm": optional_tool_context("helm", ["helm", "version", "--short"]),
    }
    blockers = []
    if not result["glab"].get("ready"):
        blockers.append({"scope": "gitlab", "reason": result["glab"].get("blocker")})
    if result["aws"].get("available") and not result["aws"].get("ready"):
        blockers.append({"scope": "aws", "reason": result["aws"].get("blocker")})
    result["blockers"] = blockers

    payload = json.dumps(result, indent=2, sort_keys=True, default=str)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
