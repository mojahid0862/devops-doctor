#!/usr/bin/env python3
"""Read-only local DevOps repo scan for CI, Docker, IaC, and secret-risk patterns."""

from __future__ import annotations

import argparse
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TARGET_NAMES = {
    ".gitlab-ci.yml",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "app.json",
    "app.config.js",
    "app.config.ts",
    "eas.json",
    "metro.config.js",
    "next.config.js",
    "next.config.ts",
    "vite.config.js",
    "vite.config.ts",
    "webpack.config.js",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Jenkinsfile",
    "azure-pipelines.yml",
    "Chart.yaml",
    "Podfile",
    "build.gradle",
    "settings.gradle",
    "AndroidManifest.xml",
}
TARGET_SUFFIXES = {".tf", ".tfvars", ".yml", ".yaml", ".Dockerfile"}
SKIP_DIRS = {
    ".dart_tool",
    ".git",
    ".gradle",
    ".next",
    ".terraform",
    ".venv",
    "Carthage",
    "DerivedData",
    "Pods",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
}

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
    ("env_reference", re.compile(r"(?i)(process\.env|import\.meta\.env|REACT_APP_|EXPO_PUBLIC_|NEXT_PUBLIC_|VITE_)")),
    ("mobile_permission_sensitive", re.compile(r"(?i)(READ_SMS|RECEIVE_SMS|SEND_SMS|ACCESS_FINE_LOCATION|RECORD_AUDIO|CAMERA)")),
    ("webhook_url", re.compile(r"(?i)https?://[^\s\"']*(webhook|hooks)[^\s\"']*")),
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
    if rule in {"mobile_permission_sensitive", "webhook_url"}:
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


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def repo_signals(root: Path, files: list[Path]) -> dict[str, Any]:
    rel_files = [str(path.relative_to(root)).replace("\\", "/") for path in files]
    package_json = root / "package.json"
    package = load_json(package_json) if package_json.exists() else None
    deps = {}
    scripts = {}
    if package:
        deps = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
        scripts = package.get("scripts", {})

    app_type = []
    if "react-native" in deps or any(path.startswith("android/") or path.startswith("ios/") for path in rel_files):
        app_type.append("mobile")
    if "expo" in deps or "app.json" in rel_files or "eas.json" in rel_files:
        app_type.append("expo")
    if any(dep in deps for dep in ("next", "vite", "react", "webpack")) or any(path.startswith("src/") for path in rel_files):
        app_type.append("web")
    if any(path.endswith(".tf") for path in rel_files):
        app_type.append("terraform")
    if any("Dockerfile" in Path(path).name or "docker-compose" in path for path in rel_files):
        app_type.append("docker")
    if ".gitlab-ci.yml" in rel_files or any(path.startswith(".gitlab/") for path in rel_files):
        app_type.append("gitlab-ci")

    return {
        "app_type": sorted(set(app_type)),
        "package_manager": "pnpm" if (root / "pnpm-lock.yaml").exists() else "yarn" if (root / "yarn.lock").exists() else "npm" if (root / "package-lock.json").exists() else None,
        "package_scripts": {name: scripts.get(name) for name in sorted(scripts) if name in {"build", "start", "test", "lint", "typecheck", "android", "ios", "web", "deploy"}},
        "has_eas": (root / "eas.json").exists(),
        "has_android": (root / "android").exists(),
        "has_ios": (root / "ios").exists(),
        "has_gitlab_ci": (root / ".gitlab-ci.yml").exists() or (root / ".gitlab").exists(),
        "has_docker": any("Dockerfile" in Path(path).name or "docker-compose" in path for path in rel_files),
        "tracked_signal_files": rel_files[:200],
    }


def signal_findings(signals: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    scripts = signals.get("package_scripts", {})
    if signals.get("has_gitlab_ci") and scripts and not any(key in scripts for key in ("test", "lint", "typecheck")):
        findings.append({"severity": "info", "rule": "package_missing_common_validation_scripts", "path": "package.json"})
    if "mobile" in signals.get("app_type", []) and not signals.get("has_eas"):
        findings.append({"severity": "info", "rule": "mobile_eas_config_not_found", "path": "eas.json"})
    if signals.get("has_docker") and "docker" not in signals.get("app_type", []):
        findings.append({"severity": "info", "rule": "docker_signal_inconsistent", "path": "."})
    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan local repo for DevOps security/reliability risk patterns.")
    parser.add_argument("--root", default=".", help="Repository root to scan.")
    parser.add_argument("--output", help="Write JSON result to this path.")
    parser.add_argument("--max-workers", type=int, default=8, help="Throttle parallel file reads; lower this on slow disks or constrained runners.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    files = [path for path in root.rglob("*") if path.is_file() and should_scan(path.relative_to(root))]
    findings: list[dict[str, Any]] = []
    max_workers = max(1, args.max_workers)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for file_findings in executor.map(lambda path: scan_file(path, root), files):
            findings.extend(file_findings)
    signals = repo_signals(root, files)
    findings.extend(signal_findings(signals))

    result = {
        "summary": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "root": str(root),
            "files_scanned": len(files),
            "app_type": signals.get("app_type", []),
            "high_findings": sum(1 for item in findings if item.get("severity") == "high"),
            "medium_findings": sum(1 for item in findings if item.get("severity") == "medium"),
        },
        "findings": findings,
        "evidence": signals,
        "blockers": [],
        "next_commands": [
            "git status --short",
            "npm run build",
            "npm run test",
        ],
        "raw": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "root": str(root),
            "files_scanned": len(files),
        },
    }
    payload = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
