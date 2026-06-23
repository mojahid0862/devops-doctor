#!/usr/bin/env python3
"""Read-only local DevOps repo scan for CI, Docker, IaC, and secret-risk patterns."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TARGET_NAMES = {
    ".gitlab-ci.yml",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Jenkinsfile",
    "azure-pipelines.yml",
    "Chart.yaml",
}
TARGET_SUFFIXES = {".tf", ".tfvars", ".yml", ".yaml", ".Dockerfile"}
SKIP_DIRS = {".git", "node_modules", ".terraform", "dist", "build", ".next", "coverage", "vendor"}

RULES = [
    ("secret_like_value", re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}")),
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key_marker", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("docker_latest_tag", re.compile(r"(?i)^\s*FROM\s+\S+:latest\b")),
    ("docker_unpinned_base", re.compile(r"(?i)^\s*FROM\s+[A-Za-z0-9./_-]+(?:\s+AS\s+\w+)?\s*$")),
    ("privileged_container", re.compile(r"(?i)\bprivileged\s*:\s*true\b")),
    ("public_cidr", re.compile(r"0\.0\.0\.0/0|::/0")),
    ("terraform_iam_wildcard", re.compile(r'(?i)(actions?|resources?)\s*=\s*\[\s*"\*"\s*\]')),
    ("s3_public_acl", re.compile(r'(?i)acl\s*=\s*"(public-read|public-read-write)"')),
    ("gitlab_prod_environment", re.compile(r"(?i)environment\s*:\s*production")),
]


def should_scan(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    if path.name in TARGET_NAMES:
        return True
    if path.suffix in TARGET_SUFFIXES:
        return True
    if path.name.startswith("Dockerfile"):
        return True
    return False


def severity(rule: str) -> str:
    if rule in {"secret_like_value", "aws_access_key_id", "private_key_marker", "public_cidr", "terraform_iam_wildcard", "s3_public_acl"}:
        return "high"
    if rule in {"privileged_container", "docker_latest_tag", "docker_unpinned_base"}:
        return "medium"
    return "info"


def scan_file(path: Path, root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return [{"severity": "info", "rule": "read_error", "path": str(path.relative_to(root)), "detail": str(exc)}]

    has_user = False
    is_dockerfile = path.name.startswith("Dockerfile") or path.suffix == ".Dockerfile"
    for number, line in enumerate(lines, 1):
        if is_dockerfile and re.search(r"(?i)^\s*USER\s+\S+", line):
            has_user = True
        for rule, pattern in RULES:
            if pattern.search(line):
                findings.append(
                    {
                        "severity": severity(rule),
                        "rule": rule,
                        "path": str(path.relative_to(root)),
                        "line": number,
                    }
                )
    if is_dockerfile and not has_user:
        findings.append({"severity": "medium", "rule": "docker_runs_as_root_by_default", "path": str(path.relative_to(root)), "line": None})
    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan local repo for DevOps security/reliability risk patterns.")
    parser.add_argument("--root", default=".", help="Repository root to scan.")
    parser.add_argument("--output", help="Write JSON result to this path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    files = [path for path in root.rglob("*") if path.is_file() and should_scan(path.relative_to(root))]
    findings: list[dict[str, Any]] = []
    for path in files:
        findings.extend(scan_file(path, root))

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "files_scanned": len(files),
        "findings": findings,
    }
    payload = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
