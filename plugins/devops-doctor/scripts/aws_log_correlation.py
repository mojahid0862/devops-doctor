#!/usr/bin/env python3
"""Correlate identified CloudWatch log events with one bounded Insights query."""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aws_stack_snapshot import bounded_int, scoped
from doctor_common import emit_result, redact, run_command, sanitize


ID_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}"
ID = re.compile(ID_PATTERN)
GROUP = re.compile(r"[A-Za-z0-9._/#][A-Za-z0-9._/#-]{0,511}")
REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,4}-[0-9]{1,2}")
ACCOUNT = re.compile(r"[0-9]{12}")
QUERY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,255}")
ACTIVE = {"Scheduled", "Running"}
TERMINAL = {"Complete", "Failed", "Cancelled", "Timeout"}
STATS = {
    "recordsScanned": "records_scanned",
    "recordsMatched": "records_matched",
    "bytesScanned": "bytes_scanned",
    "logGroupsScanned": "log_groups_scanned",
    "resultCount": "service_result_count",
}
CLEANUP_SECONDS = 3


def utc(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def epoch(value: str) -> int:
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.utcoffset() is None or date.microsecond:
            raise ValueError()
        seconds = int(date.astimezone(timezone.utc).timestamp())
        if seconds >= 0:
            return seconds
    except (ValueError, OverflowError, OSError):
        pass
    raise argparse.ArgumentTypeError("expected an ISO-8601 timestamp with timezone and whole seconds")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-group", action="append", required=True, help="Explicit log group name. Repeat for each group.")
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", help="Existing AWS CLI credential profile.")
    parser.add_argument("--account-id", required=True, help="Expected AWS account. Checked with STS before querying.")
    parser.add_argument("--start", required=True, type=epoch, help="Inclusive ISO-8601 timestamp with timezone.")
    parser.add_argument("--end", required=True, type=epoch, help="Exclusive ISO-8601 timestamp with timezone.")
    parser.add_argument("--request-id", help="Exact request ID to match.")
    parser.add_argument("--correlation-id", help="Exact correlation ID to match. Both selectors must match when supplied together.")
    parser.add_argument("--max-log-groups", type=bounded_int(1, 10), default=5)
    parser.add_argument("--max-window-minutes", type=bounded_int(1, 360), default=60)
    parser.add_argument("--max-results", type=bounded_int(1, 500), default=100)
    parser.add_argument("--max-output-bytes", type=bounded_int(4096, 65536), default=12288, help="UTF-8 JSON size limit.")
    parser.add_argument("--max-samples", type=bounded_int(0, 20), default=5)
    parser.add_argument("--max-polls", type=bounded_int(1, 30), default=10)
    parser.add_argument("--poll-interval", type=bounded_int(1, 10), default=1, help="Seconds between polls.")
    parser.add_argument("--timeout-seconds", type=bounded_int(5, 120), default=45, help="AWS command time budget including cleanup.")
    parser.add_argument("--output", help="Optional local JSON report path.")
    args = parser.parse_args(argv)
    if not REGION.fullmatch(args.region) or not ACCOUNT.fullmatch(args.account_id):
        parser.error("expected a valid AWS Region and a 12-digit account ID")
    if args.profile is not None and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,63}", args.profile):
        parser.error("expected an AWS CLI profile name without whitespace or shell characters")
    if len(args.log_group) > args.max_log_groups or sum(map(len, args.log_group)) > 2048:
        parser.error("log group count or total name length exceeds the allowed limit")
    if len(set(args.log_group)) != len(args.log_group) or any(not GROUP.fullmatch(g) for g in args.log_group):
        parser.error("expected distinct, explicit log group names")
    if not 0 < args.end - args.start <= args.max_window_minutes * 60:
        parser.error("expected start < end within the configured time window")
    selectors = (args.request_id, args.correlation_id)
    if not any(selectors) or any(
        value is not None and (not ID.fullmatch(value) or redact(value) != value) for value in selectors
    ):
        parser.error("supply a request or correlation ID using 1–128 identifier characters")
    return args


def query_string(args: argparse.Namespace) -> str:
    """Use a fixed CWLI query with only validated, quoted identifiers."""
    def identifier(fields: tuple[str, ...], fallback: str) -> str:
        # A blank or invalid alias must not hide a usable alternate ID.
        branches = ", ".join(f"{field} like /^{ID_PATTERN}$/, {field}" for field in fields)
        return f'case({branches}, coalesce({fallback}, ""))'

    predicates = [f"event_ms >= {args.start * 1000}", f"event_ms < {args.end * 1000}"]
    for field, value in (("req_id", args.request_id), ("corr_id", args.correlation_id)):
        if value is not None:
            predicates.append(f"{field} = {json.dumps(value)}")
    return (
        "fields toMillis(@timestamp) as event_ms, jsonParse(@message) as payload"
        rf" | parse @message /(?:^|[\s,])(?:RequestId|requestId|request_id)[=:]\s*(?<text_req>{ID_PATTERN})(?:$|[\s,])/"
        rf" | parse @message /(?:^|[\s,])(?:CorrelationId|correlationId|correlation_id)[=:]\s*(?<text_corr>{ID_PATTERN})(?:$|[\s,])/"
        r" | parse @message /(?:^|[\s,])(?:level|severity|logLevel)[=:]\s*(?<text_level>[A-Za-z]{1,16})(?:$|[\s,])/"
        f' | fields {identifier(("payload.requestId", "payload.request_id", "payload.RequestId"), "text_req")} as req_id,'
        f' {identifier(("payload.correlationId", "payload.correlation_id", "payload.CorrelationId"), "text_corr")} as corr_id'
        " | filter " + " and ".join(predicates)
        + ' | fields toupper(case(isempty(payload.level) = 0, payload.level,'
        ' isempty(payload.severity) = 0, payload.severity, isempty(payload.logLevel) = 0, payload.logLevel,'
        ' coalesce(text_level, ""))) as log_level,'
        ' coalesce(toInt(payload.statusCode), toInt(payload.status_code),'
        ' toInt(payload.httpStatusCode), toInt(payload.http.status_code), -1) as http_code'
        ' | fields if(log_level in ["ERROR","FATAL","CRITICAL","PANIC"]'
        ' or (http_code >= 500 and http_code < 600), 1, 0) as failure,'
        ' req_id as request_id, corr_id as correlation_id'
        " | sort event_ms asc"
        " | display event_ms, @log, request_id, correlation_id, failure"
        f" | limit {args.max_results}"
    )


def query_statistics(data: Any) -> dict[str, int | float]:
    if not isinstance(data, dict):
        return {}
    stats = {}
    for aws_key, key in STATS.items():
        value = data.get(aws_key)
        if type(value) in (int, float) and 0 <= value < 2**64 and math.isfinite(value):
            stats[key] = value
    return stats


def summarize_rows(report: dict[str, Any], args: argparse.Namespace, rows: list) -> None:
    """Count exact IDs in received rows and expose only allowlisted sample fields."""
    events = []
    invalid = 0
    expected_logs = {f"{args.account_id}:{group}" for group in args.log_group}
    for raw in rows[:args.max_results]:
        if not isinstance(raw, list) or any(
            not isinstance(cell, dict) or not isinstance(cell.get("field"), str)
            or not isinstance(cell.get("value"), str) for cell in raw
        ):
            invalid += 1
            continue
        row = {cell["field"]: cell["value"] for cell in raw}
        ms = row.get("event_ms", "")
        log = row.get("@log", "")
        failed = row.get("failure", "")
        request = row.get("request_id", "")
        correlation = row.get("correlation_id", "")
        if (len(row) != len(raw) or not re.fullmatch(r"[0-9]{1,15}", ms)
                or not args.start * 1000 <= int(ms) < args.end * 1000
                or log not in expected_logs or failed not in {"0", "1"}
                or (args.request_id is not None and request != args.request_id)
                or (args.correlation_id is not None and correlation != args.correlation_id)):
            invalid += 1
            continue
        request = request if ID.fullmatch(request) else ""
        correlation = correlation if ID.fullmatch(correlation) else ""
        events.append((int(ms), log.split(":", 1)[1], request, correlation, failed == "1"))
    events.sort()
    if invalid:
        report["coverage"]["reasons"].append("invalid_or_out_of_scope_rows")
    requests = {event[2] for event in events if event[2]}
    failed_requests = {event[2] for event in events if event[2] and event[4]}
    report["summary"].update(
        result_rows=len(rows),
        usable_rows=len(events),
        invalid_rows=invalid,
        observed_log_groups=sorted({event[1] for event in events}),
        unique_request_ids=len(requests),
        unique_correlation_ids=len({event[3] for event in events if event[3]}),
        unique_failed_request_ids=len(failed_requests),
        unique_failed_correlation_ids=len({event[3] for event in events if event[3] and event[4]}),
        failure_rows=sum(event[4] for event in events),
        rows_without_request_id=sum(not event[2] for event in events),
        failure_rows_without_request_id=sum(event[4] and not event[2] for event in events),
    )
    request_labels: dict[str, str] = {}
    correlation_labels: dict[str, str] = {}
    samples = report["evidence"]["samples"]
    first_by_group: dict[str, int] = {}
    for index, (_, log, _, _, _) in enumerate(events):
        first_by_group.setdefault(log, index)
    first = list(first_by_group.values())[:args.max_samples]
    remaining = [index for index in range(len(events)) if index not in first]
    selected = sorted(first + remaining[:args.max_samples - len(first)])
    for index in selected:
        ms, log, request, correlation, failed = events[index]
        if request:
            request_labels.setdefault(request, f"r{len(request_labels) + 1}")
        if correlation:
            correlation_labels.setdefault(correlation, f"c{len(correlation_labels) + 1}")
        samples.append({"timestamp": utc(ms / 1000), "log_group": log, "request_alias": request_labels.get(request),
                        "correlation_alias": correlation_labels.get(correlation), "failure_signal": failed})
    report["coverage"]["samples_omitted"] = len(events) - len(samples)


def classify_error(result: dict[str, Any]) -> str:
    message = str(result.get("error", "")).casefold()
    if any(marker in message for marker in ("accessdenied", "not authorized", "unauthorized", "forbidden")):
        return "access_denied"
    if message.startswith("timeout after"):
        return "timed_out"
    if any(marker in message for marker in ("expiredtoken", "unable to locate credentials", "invalidclienttokenid")):
        return "authentication_failed"
    return "failed"


def build_report(args: argparse.Namespace, aws: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": "2.0", "generated_at": utc(time.time()), "status": "partial",
        "scope": {"collector": "aws_log_correlation", "account_id": args.account_id, "region": args.region,
                  "start": utc(args.start), "end_exclusive": utc(args.end), "log_groups": args.log_group,
                  "filters": {"request_id_selected": args.request_id is not None,
                              "correlation_id_selected": args.correlation_id is not None}},
        "summary": {"result_rows": None, "query_outcome": "not_started", "count_basis": "usable_returned_rows"},
        "query": {"status": "NotStarted", "polls": 0, "statistics": {}},
        "coverage": {"complete": False, "truncated": False, "identity_verified": False, "reasons": [],
                     "source_event_coverage": "unverified",
                     "result_limit": args.max_results, "sample_limit": args.max_samples,
                     "output_byte_limit": args.max_output_bytes},
        "collection": {"complete": False},
        "evidence": {"samples": []}, "findings": [], "blockers": [],
    }
    query = report["query"]
    coverage = report["coverage"]
    deadline = time.monotonic() + args.timeout_seconds
    query_deadline = deadline - CLEANUP_SECONDS
    query_id = None

    def call(service: str, operation: str, *values: str, until: float = query_deadline) -> dict[str, Any] | None:
        remaining = until - time.monotonic()
        if remaining <= 0:
            return None
        command = scoped([service, operation, *values, "--no-paginate"], args.profile, args.region)
        return run_command([aws, *command[1:], "--output", "json"], timeout=remaining,
                           aws_max_attempts=1, aws_ignore_configured_endpoints=True)

    def finish(outcome: str, scope: str, reason: str, *, failed: bool = False) -> dict[str, Any]:
        report["status"] = "failed" if failed else "partial"
        report["summary"]["query_outcome"] = outcome
        report["blockers"].append({"scope": scope, "reason": reason})
        return report

    try:
        identity = call("sts", "get-caller-identity")
        if identity is None or not identity.get("ok"):
            outcome = classify_error(identity) if identity is not None else "timed_out"
            return finish(outcome, "identity", "AWS identity could not be verified", failed=True)
        data = identity.get("data")
        if not isinstance(data, dict) or data.get("Account") != args.account_id:
            return finish("account_mismatch", "identity", "STS account did not match the requested account", failed=True)
        coverage["identity_verified"] = True
        started = call("logs", "start-query", "--log-group-names", *args.log_group,
                       "--start-time", str(args.start), "--end-time", str(args.end),
                       "--query-string", query_string(args), "--limit", str(args.max_results))
        if started is None or not started.get("ok"):
            outcome = classify_error(started) if started is not None else "timed_out"
            if started is not None and outcome not in {"access_denied", "authentication_failed"}:
                query["start_unconfirmed"] = True
            return finish(outcome, "start_query", "Query start was not confirmed", failed=True)
        data = started.get("data")
        handle = data.get("queryId") if isinstance(data, dict) else None
        if not isinstance(handle, str) or not QUERY_ID.fullmatch(handle):
            query["start_unconfirmed"] = True
            return finish("failed", "start_query", "Missing or invalid query ID", failed=True)
        query_id = handle
        query["query_id"] = query_id
        query["status"] = "Submitted"

        for poll in range(args.max_polls):
            response = call("logs", "get-query-results", "--query-id", query_id)
            if response is None:
                return finish("timed_out", "query", "Local execution deadline reached")
            query["polls"] += 1
            if not response.get("ok"):
                outcome = classify_error(response)
                return finish(outcome, "query", "Query results could not be retrieved", failed=outcome != "timed_out")
            data = response.get("data")
            state = data.get("status") if isinstance(data, dict) else None
            query["status"] = state if isinstance(state, str) and state in ACTIVE | TERMINAL else "Unknown"
            query["statistics"] = query_statistics(data.get("statistics")) if isinstance(data, dict) else {}
            if query["status"] in ACTIVE:
                if poll + 1 < args.max_polls:
                    time.sleep(min(args.poll_interval, max(0, query_deadline - time.monotonic())))
                continue
            if query["status"] != "Complete":
                outcome = {"Cancelled": "cancelled", "Timeout": "timed_out", "Failed": "failed"}.get(query["status"], "unknown")
                return finish(outcome, "query", "AWS did not return a completed query", failed=outcome == "failed")

            rows = data.get("results")
            if not isinstance(rows, list):
                return finish("failed", "query", "Completed response lacked a results list", failed=True)
            stats = query["statistics"]
            if data.get("nextToken") or data.get("NextToken") or response.get("truncated"):
                coverage["reasons"].append("additional_results_available")
            if len(rows) >= args.max_results:
                coverage["reasons"].append("result_limit_reached")
            if stats.get("records_matched", 0) > len(rows) or stats.get("service_result_count", 0) > len(rows):
                coverage["reasons"].append("statistics_exceed_returned_rows")
            coverage["truncated"] = bool(coverage["reasons"])
            if "records_matched" in stats and stats["records_matched"] < len(rows):
                coverage["reasons"].append("matched_records_below_returned_rows")
            if "service_result_count" in stats and stats["service_result_count"] < len(rows):
                coverage["reasons"].append("service_result_count_below_returned_rows")
            if "log_groups_scanned" in stats and stats["log_groups_scanned"] < len(args.log_group):
                coverage["reasons"].append("fewer_log_groups_scanned_than_requested")
            summarize_rows(report, args, rows)
            report["summary"]["query_outcome"] = "completed" if rows or coverage["reasons"] else "empty"
            if coverage["reasons"]:
                return finish("completed", "coverage", "Returned rows do not establish complete query coverage")
            report["status"] = "complete"
            coverage["complete"] = report["collection"]["complete"] = True
            return report
        return finish(query["status"].lower(), "query", "Polling attempt limit reached")
    except KeyboardInterrupt:
        if query_id is None:
            query["start_unconfirmed"] = coverage["identity_verified"]
        return finish("cancelled", "query", "Collection interrupted", failed=query_id is None)
    finally:
        if query_id is not None and query["status"] not in TERMINAL:
            stopped = call("logs", "stop-query", "--query-id", query_id, until=deadline)
            payload = stopped.get("data") if stopped and stopped.get("ok") else None
            confirmed = isinstance(payload, dict) and payload.get("success") is True
            query["cleanup"] = "stop_acknowledged" if confirmed else "stop_unconfirmed"
            if not confirmed:
                report["blockers"].append({"scope": "cleanup", "reason": "Query may still be running"})


def bounded_output(report: dict[str, Any], budget: int) -> dict[str, Any]:
    # Match emit_result's JSON framing and measure after redaction.
    def size() -> int:
        payload = json.dumps(sanitize(report), indent=2, sort_keys=True, default=str, ensure_ascii=False) + "\n"
        return len(payload.replace("\n", os.linesep).encode("utf-8"))

    if size() <= budget:
        return report
    if report["status"] == "complete":
        report["status"] = "partial"
    report["collection"]["complete"] = False
    coverage = report["coverage"]
    coverage.update(complete=False, truncated=True)
    coverage["reasons"].append("output_byte_limit")
    samples = report["evidence"]["samples"]
    while samples and size() > budget:
        samples.pop()
        coverage["samples_omitted"] += 1
    if size() <= budget:
        return report
    return {"schema_version": report["schema_version"], "generated_at": report["generated_at"],
            "status": report["status"], "collection": report["collection"],
            "scope": {key: value for key, value in report["scope"].items() if key != "log_groups"},
            "summary": {key: value for key, value in report["summary"].items() if key != "observed_log_groups"},
            "query": report["query"],
            "coverage": {"complete": False, "truncated": True, "source_event_coverage": "unverified",
                         "output_byte_limit": budget, "scope_log_groups_omitted": True,
                         "identity_verified": coverage["identity_verified"],
                         "samples_omitted": coverage.get("samples_omitted", 0), "reasons": coverage["reasons"]},
            "blockers": [*report["blockers"], {"scope": "output", "reason": "Report exceeded output byte limit"}]}


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    aws = shutil.which("aws")
    if not aws or os.name == "nt" and Path(aws).suffix.lower() != ".exe":
        return emit_result({"status": "failed", "blockers": [
            {"scope": "aws", "reason": "Native AWS CLI executable not found in PATH"},
        ]}, args.output)
    return emit_result(bounded_output(build_report(args, aws), args.max_output_bytes), args.output)


if __name__ == "__main__":
    raise SystemExit(main())
