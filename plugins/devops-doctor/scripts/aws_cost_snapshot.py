#!/usr/bin/env python3
"""Collect read-only AWS Cost Explorer service spend summary."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def scoped(base: list[str], profile: str | None, region: str | None) -> list[str]:
    command = ["aws", *base]
    if profile:
        command.extend(["--profile", profile])
    if region:
        command.extend(["--region", region])
    return command


def run(command: list[str], timeout: int = 60) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "command": " ".join(command)}

    result: dict[str, Any] = {"ok": completed.returncode == 0, "command": " ".join(command)}
    if completed.returncode != 0:
        result["error"] = (completed.stderr or completed.stdout).strip()[-2000:]
        return result
    try:
        result["data"] = json.loads(completed.stdout) if completed.stdout.strip() else None
    except json.JSONDecodeError:
        result["data"] = completed.stdout.strip()[-4000:]
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect read-only AWS Cost Explorer summary.")
    parser.add_argument("--profile", help="AWS profile.")
    parser.add_argument("--region", default="us-east-1", help="AWS region for Cost Explorer endpoint.")
    parser.add_argument("--days", type=int, default=14, help="Lookback days. Default: 14.")
    parser.add_argument("--output", help="Write JSON result to this path.")
    return parser.parse_args()


def summarize_cost(cost_result: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    totals: dict[str, float] = {}
    data = cost_result.get("data") if cost_result.get("ok") else {}
    for day in data.get("ResultsByTime", []) if isinstance(data, dict) else []:
        for group in day.get("Groups", []):
            service = group.get("Keys", ["unknown"])[0]
            amount = float(group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0) or 0)
            totals[service] = totals.get(service, 0.0) + amount
    top = sorted(totals.items(), key=lambda item: item[1], reverse=True)[:10]
    findings = [
        {"severity": "info", "rule": "top_cost_service", "service": service, "amount": round(amount, 4)}
        for service, amount in top[:5]
        if amount > 0
    ]
    return {"top_services": [{"service": service, "amount": round(amount, 4)} for service, amount in top], "service_count": len(totals)}, findings


def main() -> int:
    args = parse_args()
    if not shutil.which("aws"):
        print("aws CLI not found in PATH.", file=sys.stderr)
        return 2

    end = date.today()
    start = end - timedelta(days=args.days)
    raw = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": args.profile,
        "region": args.region,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "identity": run(scoped(["sts", "get-caller-identity", "--output", "json"], args.profile, None)),
        "service_cost": run(
            scoped(
                [
                    "ce",
                    "get-cost-and-usage",
                    "--time-period",
                    f"Start={start.isoformat()},End={end.isoformat()}",
                    "--granularity",
                    "DAILY",
                    "--metrics",
                    "UnblendedCost",
                    "--group-by",
                    "Type=DIMENSION,Key=SERVICE",
                    "--output",
                    "json",
                ],
                args.profile,
                args.region,
            ),
            timeout=90,
        ),
    }
    cost_summary, findings = summarize_cost(raw["service_cost"])
    blockers = []
    for key, value in raw.items():
        if isinstance(value, dict) and value.get("ok") is False:
            blockers.append({"scope": key, "reason": value.get("error", "command failed")})

    snapshot = {
        "summary": {
            "profile": args.profile,
            "region": args.region,
            "start": start.isoformat(),
            "end": end.isoformat(),
            **cost_summary,
        },
        "findings": findings,
        "evidence": {"identity": raw.get("identity")},
        "blockers": blockers,
        "next_commands": ["aws ce get-cost-and-usage --granularity DAILY --metrics UnblendedCost"],
        "raw": raw,
    }

    payload = json.dumps(snapshot, indent=2, sort_keys=True, default=str)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
