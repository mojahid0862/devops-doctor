#!/usr/bin/env python3
"""Collect bounded AWS Cost Explorer spend with exact decimal amounts."""
from __future__ import annotations

import argparse
import json
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from doctor_common import collect_status, emit_result, run_command

DIMENSIONS = {"SERVICE", "REGION", "USAGE_TYPE", "OPERATION", "LINKED_ACCOUNT"}
MAX_PAGES = 100


def scoped(base: list[str], profile: str | None, region: str | None) -> list[str]:
    command = ["aws", *base]
    if profile:
        command += ["--profile", profile]
    if region:
        command += ["--region", region]
    return command


def run(command: list[str], timeout: int = 60) -> dict[str, Any]:
    return run_command(command, timeout=timeout)


def positive_days(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--days must be an integer") from exc
    if not 1 <= number <= 366:
        raise argparse.ArgumentTypeError("--days must be between 1 and 366")
    return number


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", help="AWS profile.")
    parser.add_argument("--region", default="us-east-1", help="Cost Explorer endpoint region.")
    parser.add_argument("--days", type=positive_days, help="UTC lookback days, 1-366; default 14. Exclusive with --start/--end.")
    parser.add_argument("--start", help="Inclusive UTC date, YYYY-MM-DD; requires --end.")
    parser.add_argument("--end", help="Exclusive UTC date, YYYY-MM-DD; requires --start.")
    parser.add_argument("--group-by", nargs="+", default=["SERVICE"], help="One or two CE dimensions, comma- or space-separated: SERVICE REGION USAGE_TYPE OPERATION LINKED_ACCOUNT.")
    parser.add_argument("--service", help="Filter by exact Cost Explorer SERVICE dimension value.")
    parser.add_argument("--compare-previous", action="store_true", help="Compare against the immediately preceding interval of equal length.")
    parser.add_argument("--output", help="Write sanitized JSON to this path.")
    args = parser.parse_args(argv)
    today = datetime.now(timezone.utc).date()
    if bool(args.start) != bool(args.end):
        parser.error("--start and --end must be supplied together")
    if args.start and args.days is not None:
        parser.error("use either --days or --start/--end")
    if args.start:
        try:
            start, end = date.fromisoformat(args.start), date.fromisoformat(args.end)
        except ValueError:
            parser.error("--start and --end must be YYYY-MM-DD dates")
        if start.isoformat() != args.start or end.isoformat() != args.end:
            parser.error("--start and --end must be YYYY-MM-DD dates")
    else:
        end = today
        start = end - timedelta(days=args.days or 14)
    if not 1 <= (end - start).days <= 366 or end > today:
        parser.error("date interval must be 1-366 days and --end cannot be in the future")
    groups = [part.strip().upper() for value in args.group_by for part in value.split(",") if part.strip()]
    if not 1 <= len(groups) <= 2 or len(set(groups)) != len(groups) or not set(groups) <= DIMENSIONS:
        parser.error("--group-by requires one or two distinct supported dimensions")
    args.start, args.end, args.group_by = start, end, groups
    return args


def fetch_cost(args: argparse.Namespace, start: date, end: date) -> dict[str, Any]:
    base = ["ce", "get-cost-and-usage", "--time-period", f"Start={start.isoformat()},End={end.isoformat()}",
            "--granularity", "DAILY", "--metrics", "UnblendedCost", "--group-by",
            *[f"Type=DIMENSION,Key={dimension}" for dimension in args.group_by], "--output", "json"]
    if args.service:
        base += ["--filter", json.dumps({"Dimensions": {"Key": "SERVICE", "Values": [args.service]}})]
    periods, page_results = [], []
    token = None
    seen_tokens = set()
    for _ in range(MAX_PAGES):
        command = scoped(base + (["--next-page-token", token] if token else []), args.profile, args.region)
        page = run(command, timeout=90)
        page_results.append(page)
        if not page.get("ok"):
            return {"ok": False, "error": page.get("error", "Cost Explorer request failed"),
                    "data": {"ResultsByTime": periods}, "truncated": bool(periods), "pages": len(page_results)}
        data = page.get("data")
        if not isinstance(data, dict) or not isinstance(data.get("ResultsByTime"), list):
            return {"ok": False, "error": "Cost Explorer response lacks ResultsByTime", "truncated": bool(periods),
                    "data": {"ResultsByTime": periods}, "pages": len(page_results)}
        periods.extend(data["ResultsByTime"])
        token = data.get("NextPageToken")
        if not token:
            return {"ok": True, "data": {"ResultsByTime": periods}, "truncated": False,
                    "pages": len(page_results), "duration_ms": sum(page.get("duration_ms", 0) for page in page_results)}
        if token in seen_tokens:
            break
        seen_tokens.add(token)
    return {"ok": True, "data": {"ResultsByTime": periods}, "truncated": True, "pages": len(page_results),
            "coverage": {"complete": False, "reason": "pagination limit or repeated page token"}}


def amount_value(metric: dict[str, Any]) -> tuple[Decimal, str]:
    try:
        amount = Decimal(str(metric["Amount"]))
    except (KeyError, InvalidOperation, ValueError) as exc:
        raise ValueError("Cost Explorer returned an invalid amount") from exc
    if not amount.is_finite() or not metric.get("Unit"):
        raise ValueError("Cost Explorer returned a non-finite amount or missing currency")
    return amount, str(metric["Unit"])


def summarize_cost(cost_result: dict[str, Any], dimensions: list[str] | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    dimensions = dimensions or ["SERVICE"]
    if not cost_result.get("ok"):
        return {"total": None, "currency": None, "totals_by_currency": [], "top_groups": [], "estimated": None}, []
    data = cost_result.get("data", {})
    grouped: dict[tuple[tuple[str, ...], str], Decimal] = {}
    totals: dict[str, Decimal] = {}
    estimated_periods = set()
    periods = data.get("ResultsByTime", [])
    for period in periods:
        if period.get("Estimated"):
            estimated_periods.add(period.get("TimePeriod", {}).get("Start", "unknown"))
        groups = period.get("Groups", [])
        if not groups:
            metric = period.get("Total", {}).get("UnblendedCost")
            if metric:
                amount, currency = amount_value(metric)
                totals[currency] = totals.get(currency, Decimal(0)) + amount
        for group in groups:
            keys = tuple(str(key) for key in group.get("Keys", []))
            if len(keys) != len(dimensions):
                raise ValueError("Cost Explorer group keys do not match requested dimensions")
            amount, currency = amount_value(group.get("Metrics", {}).get("UnblendedCost", {}))
            key = (keys, currency)
            grouped[key] = grouped.get(key, Decimal(0)) + amount
            totals[currency] = totals.get(currency, Decimal(0)) + amount
    ordered = sorted(grouped.items(), key=lambda item: (item[0][1], -item[1], item[0][0]))
    top = [{"dimensions": dict(zip(dimensions, keys)), "amount": str(amount), "currency": currency}
           for (keys, currency), amount in ordered[:10]]
    currency = next(iter(totals)) if len(totals) == 1 else None
    summary = {"metric": "UnblendedCost", "group_by": dimensions, "group_count": len(grouped),
               "total": str(totals[currency]) if currency else None, "currency": currency,
               "totals_by_currency": [{"currency": unit, "amount": str(amount)} for unit, amount in sorted(totals.items())],
               "mixed_currencies": len(totals) > 1, "estimated": bool(estimated_periods),
               "estimated_periods": sorted(estimated_periods), "top_groups": top}
    if dimensions == ["SERVICE"]:
        summary["top_services"] = [{"service": item["dimensions"]["SERVICE"], "amount": item["amount"], "currency": item["currency"]} for item in top]
        summary["service_count"] = len({keys[0] for keys, _ in grouped})
    findings = [{"severity": "info", "rule": "top_cost_group", **item} for item in top[:5] if Decimal(item["amount"]) > 0]
    return summary, findings


def compare_cost(current: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    current_totals = {item["currency"]: Decimal(item["amount"]) for item in current.get("totals_by_currency", [])}
    previous_totals = {item["currency"]: Decimal(item["amount"]) for item in previous.get("totals_by_currency", [])}
    if not current_totals or set(current_totals) != set(previous_totals):
        return {"available": False, "reason": "matching currency totals unavailable"}
    changes = []
    for currency, amount in sorted(current_totals.items()):
        baseline = previous_totals[currency]
        delta = amount - baseline
        percent = str((delta / baseline * 100).quantize(Decimal("0.01"))) if baseline else None
        changes.append({"currency": currency, "current": str(amount), "previous": str(baseline),
                        "delta": str(delta), "percent_change": percent})
    return {"available": True, "changes": changes, "estimated": bool(current.get("estimated") or previous.get("estimated"))}


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    identity = run(scoped(["sts", "get-caller-identity", "--output", "json"], args.profile, args.region))
    result = {"summary": {"profile": args.profile, "region": args.region, "start": args.start.isoformat(),
                           "end": args.end.isoformat(), "end_exclusive": True, "service_filter": args.service},
              "findings": [], "evidence": {"identity": identity}, "blockers": [], "next_commands": [], "raw": {}}
    if not identity.get("ok") or not isinstance(identity.get("data"), dict) or not identity["data"].get("Account"):
        result["status"] = "failed"
        result["blockers"] = [{"scope": "identity", "reason": identity.get("error", "STS response lacks Account")}]
        return result
    intervals = {"service_cost": (args.start, args.end)}
    if args.compare_previous:
        intervals["previous_cost"] = (args.start - (args.end - args.start), args.start)
    with ThreadPoolExecutor(max_workers=len(intervals)) as pool:
        futures = {key: pool.submit(fetch_cost, args, *interval) for key, interval in intervals.items()}
        raw = {key: future.result() for key, future in futures.items()}
    result["raw"] = raw
    summaries = {}
    for key, value in raw.items():
        try:
            summaries[key], findings = summarize_cost(value, args.group_by)
        except ValueError as exc:
            value.update(ok=False, error=str(exc))
            summaries[key], findings = summarize_cost(value, args.group_by)
        if not value.get("ok"):
            result["blockers"].append({"scope": key, "reason": value.get("error", "cost collection failed")})
        if key == "service_cost":
            result["summary"].update(summaries[key])
            result["findings"] = findings
    if args.compare_previous:
        comparison = compare_cost(summaries["service_cost"], summaries["previous_cost"])
        comparison.update(start=intervals["previous_cost"][0].isoformat(), end=args.start.isoformat(), end_exclusive=True)
        if any(not value.get("ok") or value.get("truncated") for value in raw.values()):
            comparison = {"available": False, "reason": "one or both cost intervals are incomplete", "start": comparison["start"], "end": comparison["end"]}
        result["summary"]["comparison"] = comparison
    result["status"] = collect_status({"raw": raw, "blockers": result["blockers"]})
    return result


def main() -> int:
    args = parse_args()
    if not shutil.which("aws"):
        return emit_result({"status": "failed", "blockers": [{"scope": "aws", "reason": "aws CLI not found in PATH"}]}, args.output)
    return emit_result(build_report(args), args.output)


if __name__ == "__main__":
    raise SystemExit(main())
