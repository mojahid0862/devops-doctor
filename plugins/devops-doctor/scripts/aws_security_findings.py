#!/usr/bin/env python3
"""Collect bounded AWS Security Hub and GuardDuty findings for one account and Region."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aws_stack_snapshot import bounded_int, scoped
from doctor_common import MASK, emit_result, redact, result_payload, run_command


ACCOUNT = re.compile(r"[0-9]{12}")
REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,4}-[0-9]{1,2}")
DETECTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,299}")
SEVERITY_ORDER = {label: rank for rank, label in enumerate(
    ("FATAL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "OTHER", "UNKNOWN")
)}
# Keep identity fields only. AccessKey findings retain the IAM principal ID.
GUARD_RESOURCES = {
    "InstanceDetails": ("EC2Instance", ("InstanceId",)),
    "AccessKeyDetails": ("IAMPrincipal", ("PrincipalId",)),
    "S3BucketDetails": ("S3Bucket", ("Arn", "Name")),
    "EksClusterDetails": ("EKSCluster", ("Arn", "Name")),
    "EcsClusterDetails": ("ECSCluster", ("Arn", "Name")),
    "EcsClusterDetails.TaskDetails": ("ECSTask", ("Arn",)),
    "ContainerDetails": ("Container", ("Id",)),
    "KubernetesDetails.KubernetesWorkloadDetails": ("KubernetesWorkload", ("Uid", "Name")),
    "LambdaDetails": ("LambdaFunction", ("FunctionArn", "FunctionName")),
    "RdsDbInstanceDetails": ("RDSInstance", ("DbInstanceArn", "DbInstanceIdentifier")),
    "RdsLimitlessDbDetails": ("RDSShardGroup", ("DbShardGroupArn", "DbShardGroupIdentifier")),
    "EbsVolumeDetails.ScannedVolumeDetails": ("EBSVolume", ("VolumeArn",)),
    "EbsVolumeDetails.SkippedVolumeDetails": ("EBSVolume", ("VolumeArn",)),
    "EbsSnapshotDetails": ("EBSSnapshot", ("SnapshotArn",)),
    "Ec2ImageDetails": ("EC2Image", ("ImageArn",)),
    "RecoveryPointDetails": ("BackupRecoveryPoint", ("RecoveryPointArn",)),
    "BedrockGuardrailDetails.Guardrails": ("BedrockGuardrail", ("Arn",)),
    "ModelDetails": ("Model", ("ModelId",)),
}
LIST_RESOURCES = {"S3BucketDetails", "EbsVolumeDetails.ScannedVolumeDetails",
                  "EbsVolumeDetails.SkippedVolumeDetails", "BedrockGuardrailDetails.Guardrails", "ModelDetails"}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account-id", required=True, help="Expected STS account.")
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", help="Existing AWS CLI credential profile.")
    parser.add_argument("--service", action="append", choices=["securityhub", "guardduty"],
                        help="Repeat to select services. Default: both.")
    parser.add_argument("--securityhub-api", choices=["v2", "cspm"], default="v2")
    parser.add_argument("--max-findings", type=bounded_int(1, 250), default=50,
                        help="Maximum findings or listed IDs examined per service.")
    parser.add_argument("--max-pages", type=bounded_int(1, 20), default=5, help="Finding pages per service.")
    parser.add_argument("--page-size", type=bounded_int(1, 50), default=25)
    parser.add_argument("--timeout-seconds", type=bounded_int(5, 180), default=60, help="Shared AWS CLI time budget.")
    parser.add_argument("--max-output-bytes", type=bounded_int(4096, 1048576), default=65536,
                        help="Byte limit for each output.")
    parser.add_argument("--evidence-dir", type=Path, help="Optional new private local directory for exact identifiers.")
    parser.add_argument("--output", type=Path, help="Optional path for the redacted summary.")
    args = parser.parse_args(argv)
    if not ACCOUNT.fullmatch(args.account_id) or not REGION.fullmatch(args.region):
        parser.error("expected a 12-digit AWS account ID and AWS Region")
    if args.profile and (args.profile.startswith("-") or not args.profile.isprintable() or len(args.profile) > 128):
        parser.error("invalid AWS CLI profile")
    args.services = tuple(dict.fromkeys(args.service or ("securityhub", "guardduty")))
    if args.evidence_dir and args.output:
        private = args.evidence_dir.resolve()
        if args.output.resolve().is_relative_to(private):
            parser.error("write the summary outside the private evidence directory")
    return args


def lookup(value: Any, path: str) -> Any:
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def safe_text(value: Any, limit: int = 2048) -> str | None:
    if isinstance(value, str) and value and len(value) <= limit and value.isprintable() and redact(value) == value:
        return value if value.strip() and value != MASK else None
    return None


def timestamp(value: Any) -> datetime | None:
    try:
        if type(value) is int and 0 <= value < 253402300799000:
            return datetime.fromtimestamp(value / 1000, timezone.utc)
        if isinstance(value, str) and len(value) <= 48:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.utcoffset() is not None:
                return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    return None


def numeric(value: Any, maximum: int) -> int | float | None:
    return value if type(value) in (int, float) and 0 <= value <= maximum else None


def field_projection(paths: tuple[str, ...]) -> str:
    return "{" + ",".join(f"{path.rsplit('.', 1)[-1]}:{path}" for path in paths) + "}"


V2_PROJECTION = (
    "{NextToken:NextToken,Findings:map(&{Id:finding_info.uid,ProductId:metadata.product.uid,"
    "EventId:metadata.uid,AccountId:cloud.account.uid,Region:cloud.region,Severity:severity,"
    "Score:severity_id,Status:status,StatusId:status_id,CreatedAt:finding_info.created_time,"
    "UpdatedAt:finding_info.modified_time,FirstSeen:finding_info.first_seen_time,"
    "LastSeen:finding_info.last_seen_time,EventTime:time,Class:class_name,"
    "Resources:resources[*].{Id:uid,AlternateId:uid_alt,Type:type,Region:region,OwnerAccount:owner.account.uid}},Findings)}"
)
CSPM_PROJECTION = (
    "{NextToken:NextToken,Findings:map(&{Id:Id,ProductId:ProductArn,AccountId:AwsAccountId,"
    "Region:Region,Severity:Severity.Label,Score:Severity.Normalized,Status:Workflow.Status,"
    "RecordState:RecordState,CreatedAt:CreatedAt,UpdatedAt:UpdatedAt,FirstSeen:FirstObservedAt,"
    "LastSeen:LastObservedAt,Resources:Resources[*].{Id:Id,Type:Type,Region:Region}},Findings)}"
)
GUARD_PROJECTION = (
    "{Findings:map(&{Id:Id,Arn:Arn,AccountId:AccountId,Region:Region,Score:Severity,"
    "Archived:Service.Archived,Class:Type,CreatedAt:CreatedAt,UpdatedAt:UpdatedAt,"
    "FirstSeen:Service.EventFirstSeen,LastSeen:Service.EventLastSeen,ResourceType:Resource.ResourceType,"
    "DetectorId:Service.DetectorId,"
    "SequenceResources:Service.Sequence.Resources[*].{Id:Uid,Type:ResourceType,Region:Region,OwnerAccount:AccountId},"
    "Resources:{" + ",".join(
        f"r{i}:Resource.{path}{'[*].' if path in LIST_RESOURCES else '.'}{field_projection(fields)}"
        for i, (path, (_, fields)) in enumerate(GUARD_RESOURCES.items())
    ) + "}},Findings)}"
)


def resource_rows(rows: Any) -> tuple[list[dict], bool]:
    if not isinstance(rows, list):
        return [], True
    resources = []
    invalid = not rows or len(rows) > 50
    for entry in rows[:50]:
        identifier = safe_text(lookup(entry, "Id")) or safe_text(lookup(entry, "AlternateId"))
        if not identifier:
            invalid = True
            continue
        account = entry.get("OwnerAccount")
        resources.append({"id": identifier, "alternate_id": safe_text(entry.get("AlternateId")),
                          "type": safe_text(entry.get("Type"), 128), "region": safe_text(entry.get("Region"), 32),
                          "account_id": account if isinstance(account, str) and ACCOUNT.fullmatch(account) else None})
    return resources, invalid


def normalize_resources(item: dict, service: str) -> tuple[list[dict], bool]:
    rows = item.get("Resources")
    if service != "guardduty":
        return resource_rows(rows)
    sequence = item.get("SequenceResources")
    resources, invalid = resource_rows(sequence) if sequence is not None else ([], False)
    seen = {resource["id"] for resource in resources}
    for index, (kind, fields) in enumerate(GUARD_RESOURCES.values()):
        value = rows.get(f"r{index}") if isinstance(rows, dict) else None
        entries = value if isinstance(value, list) else [value]
        for entry in entries[:50]:
            if entry is None or (isinstance(entry, dict) and all(value is None for value in entry.values())):
                continue
            identifier = next((value for key in fields if (value := safe_text(lookup(entry, key)))), None)
            if not identifier:
                invalid = True
            elif identifier not in seen:
                resources.append({"id": identifier, "type": kind})
                seen.add(identifier)
        invalid |= len(entries) > 50
    return resources[:50], invalid or len(resources) > 50 or not resources


def normalize(item: dict, service: str) -> tuple[dict, bool]:
    score = numeric(item.get("Score"), 10 if service == "guardduty" else 100)
    label = safe_text(item.get("Severity"), 32)
    status = safe_text(item.get("Status"), 80)
    category = safe_text(item.get("Class"), 256)
    priority = None
    if service == "guardduty":
        if score is not None and score >= 1:
            label = next(label for minimum, label in ((9, "CRITICAL"), (7, "HIGH"), (4, "MEDIUM"), (1, "LOW"))
                         if score >= minimum)
        archived = item.get("Archived")
        status = ("ARCHIVED" if archived else "ACTIVE") if type(archived) is bool else None
        if category and category.startswith("AttackSequence:"):
            priority = "attack_sequences"
    elif category == "Exposure":
        priority = "exposures"
    resources, resource_gap = normalize_resources(item, service)
    times = {key: item[field] for key, field in (
        ("created_at", "CreatedAt"), ("updated_at", "UpdatedAt"), ("first_seen", "FirstSeen"),
        ("last_seen", "LastSeen"), ("event_time", "EventTime"),
    ) if timestamp(item.get(field)) is not None}
    status_id = numeric(item.get("StatusId"), 999)
    record = {
        "id": safe_text(item.get("Id")), "source_service": service, "source_product_id": safe_text(item.get("ProductId")),
        "source_event_id": safe_text(item.get("EventId")), "finding_arn": safe_text(item.get("Arn")),
        "account_id": item["AccountId"], "region": item["Region"],
        "severity": {"label": label, "score": score}, "status": status, "status_id": status_id,
        "record_state": safe_text(item.get("RecordState"), 32),
        "resources": resources, "resource_type": safe_text(item.get("ResourceType"), 128),
        "timestamps": times, "finding_type": category, "priority": priority,
    }
    incomplete = (resource_gap or not times or not (status or status_id is not None or record["record_state"])
                  or label is None or label.upper() not in SEVERITY_ORDER)
    return record, incomplete


class ServiceResults:
    def __init__(self, args: argparse.Namespace, name: str) -> None:
        self.args = args
        self.name = name
        self.records: dict[tuple[str | None, str], dict] = {}
        self.issues: set[str] = set()
        self.truncated = False
        self.pages = self.examined = self.duplicates = self.invalid = 0
        self.outcome = "not_started"

    def flag(self, reason: str, *, truncated: bool = False) -> None:
        self.issues.add(reason)
        self.truncated |= truncated

    def add(self, item: Any) -> None:
        if (not isinstance(item, dict) or not safe_text(item.get("Id"))
                or item.get("AccountId") != self.args.account_id or item.get("Region") != self.args.region):
            self.invalid += 1
            self.flag("invalid_or_out_of_scope_finding")
            return
        if self.name == "securityhub" and not safe_text(item.get("ProductId")):
            self.invalid += 1
            self.flag("finding_provider_unverified")
            return
        record, incomplete = normalize(item, self.name)
        if incomplete:
            self.flag("finding_fields_incomplete")
        key = (record["source_product_id"], record["id"])
        previous = self.records.get(key)
        if previous is not None:
            self.duplicates += 1
            if record == previous:
                return
            self.flag("conflicting_duplicate")
            def updated(finding: dict) -> datetime:
                times = finding["timestamps"]
                return next((timestamp(times[key]) for key in ("updated_at", "event_time", "created_at") if key in times),
                            datetime.min.replace(tzinfo=timezone.utc))
            if updated(record) <= updated(previous):
                return
        self.records[key] = record

    def summary(self) -> dict:
        records = self.records.values()
        severities = Counter(
            label if (label := (record["severity"]["label"] or "").upper()) in SEVERITY_ORDER else "UNKNOWN"
            for record in records
        )
        return {"outcome": self.outcome, "complete": self.outcome in {"empty", "complete"} and not self.issues,
                "truncated": self.truncated, "reasons": sorted(self.issues), "pages": self.pages,
                "examined": self.examined, "findings_collected": len(self.records), "duplicate_findings": self.duplicates,
                "invalid_findings": self.invalid, "by_severity": dict(severities),
                "priority_counts": dict(Counter(record["priority"] for record in records if record["priority"]))}


def error_outcome(result: dict) -> str:
    error = str(result.get("error", "")).casefold()
    if any(code in error for code in ("accessdenied", "invalidaccess", "not authorized", "unauthorized", "forbidden")):
        return "access_denied"
    if "resourcenotfoundexception" in error:
        return "resource_not_found"
    if error == "invalid or empty json response":
        return "malformed_response"
    if error.startswith("timeout after"):
        return "timed_out"
    if any(code in error for code in ("expiredtoken", "invalidclienttokenid", "unable to locate credentials")):
        return "authentication_failed"
    return "api_failure"


def page_scan(service: ServiceResults, read, items_key: str, consume) -> None:
    seen_tokens: set[str] = set()
    token = None
    for _ in range(service.args.max_pages):
        size = min(service.args.page_size, service.args.max_findings - service.examined)
        body = {"MaxResults": size}
        if token is not None:
            body["NextToken"] = token
        data, error = read(body)
        if error:
            service.outcome = error
            service.flag("finding_page_unavailable", truncated=bool(service.pages) or error == "timed_out")
            return
        rows = data.get(items_key)
        if not isinstance(rows, list):
            service.outcome = "malformed_response"
            service.flag("missing_finding_list", truncated=bool(service.pages))
            return
        service.pages += 1
        service.examined += min(len(rows), size)
        error = consume(rows[:size])
        if error:
            service.outcome = error
            return
        if len(rows) > size:
            service.flag("page_exceeded_requested_limit", truncated=True)
            break
        token = data.get("NextToken")
        if token is None:
            break
        if not isinstance(token, str) or not token.isprintable() or not token.strip() or len(token) > 8192 or token in seen_tokens:
            service.flag("invalid_or_repeated_continuation", truncated=True)
            break
        seen_tokens.add(token)
        if service.examined >= service.args.max_findings:
            service.flag("finding_limit", truncated=True)
            break
    else:
        service.flag("page_limit", truncated=True)
    service.outcome = ("truncated" if service.truncated else "partial" if service.issues
                       else "complete" if service.records else "empty")


def securityhub(service: ServiceResults, call) -> None:
    args = service.args
    v2 = args.securityhub_api == "v2"
    describe = "describe-security-hub-v2" if v2 else "describe-hub"
    data, error = call("securityhub", describe, projection="{HubArn:HubV2Arn}" if v2 else "{HubArn:HubArn}")
    arn = data.get("HubArn")
    if error or not isinstance(arn, str) or not re.fullmatch(
        rf"arn:aws(?:-[a-z0-9-]+)?:securityhub:{args.region}:{args.account_id}:{'hubv2' if v2 else 'hub'}(?:/[^ ]+)?",
        arn,
    ):
        service.outcome = "not_configured" if error == "resource_not_found" else error or "malformed_response"
        service.flag("securityhub_configuration_unavailable")
        return
    scope = (("cloud.account.uid", args.account_id), ("cloud.region", args.region)) if v2 else (
        ("AwsAccountId", args.account_id), ("Region", args.region),
    )
    if v2:
        filters = {"CompositeFilters": [{"Operator": "AND", "StringFilters": [
            {"FieldName": key, "Filter": {"Value": value, "Comparison": "EQUALS"}} for key, value in scope
        ]}]}
    else:
        filters = {key: [{"Value": value, "Comparison": "EQUALS"}] for key, value in scope}

    def read(body: dict):
        return call("securityhub", "get-findings-v2" if v2 else "get-findings",
                    body={**body, "Filters": filters}, projection=V2_PROJECTION if v2 else CSPM_PROJECTION)

    def consume(rows: list) -> None:
        for row in rows:
            service.add(row)

    page_scan(service, read, "Findings", consume)


def guardduty(service: ServiceResults, call) -> None:
    args = service.args
    data, error = call("guardduty", "list-detectors", body={"MaxResults": 2},
                       projection="{DetectorIds:DetectorIds,NextToken:NextToken}")
    if error:
        service.outcome = error
        service.flag("detector_discovery_failed")
        return
    detectors = data.get("DetectorIds")
    if data.get("NextToken") is not None or not isinstance(detectors, list) or len(detectors) > 1:
        service.outcome = "malformed_response"
        service.flag("detector_discovery_incomplete", truncated=data.get("NextToken") is not None)
        return
    if not detectors:
        service.outcome = "not_configured"
        service.flag("no_regional_detector")
        return
    detector = detectors[0]
    if not isinstance(detector, str) or not DETECTOR.fullmatch(detector):
        service.outcome = "malformed_response"
        service.flag("invalid_detector_id")
        return
    data, error = call("guardduty", "get-detector", body={"DetectorId": detector}, projection="{Status:Status}")
    if error or data.get("Status") != "ENABLED":
        service.outcome = "disabled" if not error and data.get("Status") == "DISABLED" else error or "malformed_response"
        service.flag("detector_unavailable")
        return
    seen_ids: set[str] = set()

    def read(body: dict):
        return call("guardduty", "list-findings", body={
            **body, "DetectorId": detector, "FindingCriteria": {"Criterion": {
                "accountId": {"Equals": [args.account_id]}, "region": {"Equals": [args.region]},
            }},
        }, projection="{FindingIds:FindingIds,NextToken:NextToken}")

    def consume(rows: list) -> str | None:
        ids = set()
        for value in rows:
            identifier = safe_text(value, 300)
            if identifier is None:
                service.invalid += 1
                service.flag("invalid_listed_finding_id")
            elif identifier in seen_ids:
                service.duplicates += 1
            else:
                ids.add(identifier)
                seen_ids.add(identifier)
        if not ids:
            return None
        data, error = call("guardduty", "get-findings",
                           body={"DetectorId": detector, "FindingIds": sorted(ids)}, projection=GUARD_PROJECTION)
        if error or not isinstance(data.get("Findings"), list):
            service.flag("finding_details_unavailable", truncated=True)
            return error or "malformed_response"
        if len(data["Findings"]) > len(ids):
            service.flag("details_exceeded_requested_limit", truncated=True)
        received = set()
        for item in data["Findings"][:len(ids)]:
            identifier = safe_text(lookup(item, "Id"), 300)
            arn = lookup(item, "Arn")
            expected_suffix = f":guardduty:{args.region}:{args.account_id}:detector/{detector}/finding/{identifier}"
            if (identifier in ids and lookup(item, "DetectorId") in (None, detector)
                    and (arn is None or isinstance(arn, str) and arn.startswith("arn:") and arn.endswith(expected_suffix))):
                received.add(identifier)
                service.add(item)
            else:
                service.invalid += 1
                service.flag("unrequested_finding_details")
        if received != ids:
            service.flag("listed_finding_details_missing", truncated=True)
        return None

    page_scan(service, read, "FindingIds", consume)


def cli_history_outcome(aws: str, profile: str | None, region: str, timeout: float) -> str | None:
    # The CLI can persist full API responses before applying its output projection.
    if timeout <= 0:
        return "timed_out"
    command = scoped(["configure", "get", "cli_history"], profile, region)
    result = run_command([aws, *command[1:]], timeout=timeout, parse_json=False)
    if result.get("ok"):
        setting = result.get("data")
        if setting == "disabled":
            return None
        return "cli_history_enabled" if setting == "enabled" else "cli_history_unverified"
    if result.get("returncode") == 1 and result.get("error") == "command exited 1":
        return None  # Unset; the AWS CLI defaults to disabled.
    outcome = error_outcome(result)
    return outcome if outcome == "timed_out" else "cli_history_unverified"


def build_report(args: argparse.Namespace, aws: str | None) -> tuple[dict, list[dict]]:
    deadline = time.monotonic() + args.timeout_seconds
    services = {name: ServiceResults(args, name) for name in args.services}
    report = {"schema_version": "2.0", "generated_at": datetime.now(timezone.utc).isoformat(),
              "scope": {"collector": "aws_security_findings", "account_id": args.account_id, "region": args.region,
                        "securityhub_api": args.securityhub_api if "securityhub" in services else None},
              "coverage": {"scope": "reported_finding_account_and_region",
                           "event_origin_verified": False,
                           "related_resources_may_span_accounts_or_regions": True,
                           "security_assessment": "not_performed", "identity_verified": False,
                           "max_findings_per_service": args.max_findings, "max_pages_per_service": args.max_pages,
                           "page_size": args.page_size, "timeout_seconds": args.timeout_seconds,
                           "max_output_bytes": args.max_output_bytes},
              "summary": {"services": {}}, "findings": [], "evidence": {"written": False}, "blockers": []}

    def call(service: str, operation: str, *, body: dict | None = None, projection: str):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {}, "timed_out"
        command = scoped([service, operation, "--no-paginate", "--output", "json", "--query", projection],
                         args.profile, args.region)
        if body is not None:
            command.extend(["--cli-input-json", json.dumps(body, ensure_ascii=True)])
        result = run_command([aws, *command[1:]], timeout=remaining, aws_max_attempts=1,
                             aws_ignore_configured_endpoints=True, sanitize_json=False)
        if not result.get("ok"):
            return {}, error_outcome(result)
        data = result.get("data")
        return (data, None) if isinstance(data, dict) else ({}, "malformed_response")

    error = cli_history_outcome(aws, args.profile, args.region, deadline - time.monotonic()) if aws else "aws_cli_unavailable"
    if error:
        report["status"] = "failed"
        report["blockers"].append({"scope": "aws_cli", "reason": error})
        report["summary"]["services"] = {name: service.summary() for name, service in services.items()}
        return report, []
    identity, error = call("sts", "get-caller-identity", projection="{Account:Account}")
    if error or identity.get("Account") != args.account_id:
        report["status"] = "failed"
        report["blockers"].append({"scope": "identity", "reason": error or "account_mismatch"})
        report["summary"]["services"] = {name: service.summary() for name, service in services.items()}
        return report, []
    report["coverage"]["identity_verified"] = True
    authentication_failed = False
    for name, service in services.items():
        if authentication_failed:
            service.outcome = "authentication_failed"
            service.flag("skipped_after_authentication_failure")
            continue
        (securityhub if name == "securityhub" else guardduty)(service, call)
        authentication_failed = service.outcome == "authentication_failed"
    statuses = {name: service.summary() for name, service in services.items()}
    report["summary"]["services"] = statuses
    records = [record for service in services.values() for record in service.records.values()]
    records.sort(key=lambda record: (
        record["priority"] is None,
        SEVERITY_ORDER.get((record["severity"]["label"] or "").upper(), SEVERITY_ORDER["UNKNOWN"]),
    ))
    for name, status in statuses.items():
        if not status["complete"]:
            report["blockers"].append({"scope": name, "reason": status["outcome"]})
    observed = {"complete", "empty", "partial", "truncated", "disabled", "not_configured"}
    if all(status["complete"] for status in statuses.values()):
        report["status"] = "complete"
    elif any(service.records or service.outcome in observed for service in services.values()):
        report["status"] = "partial"
    else:
        report["status"] = "failed"
    return report, records


def save_evidence(path: Path, report: dict, records: list[dict], limit: int) -> dict:
    if os.name == "nt":
        minimum = {(3, 10): (3, 10, 15), (3, 11): (3, 11, 10), (3, 12): (3, 12, 4)}
        if sys.version_info[:3] < minimum.get(sys.version_info[:2], (3, 13, 0)):
            raise PermissionError("Python does not support private directory creation on this Windows version")
    # Compact encoding keeps the bound in bytes, including JSON framing.
    def encode(value: Any) -> bytes:
        return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")

    metadata = {"schema_version": report["schema_version"], "generated_at": report["generated_at"],
                "scope": report["scope"], "coverage": report["coverage"],
                "collection": {"service_status": report["status"]},
                "services": report["summary"]["services"]}
    header = encode(metadata)[:-1] + b',"findings":['
    trailer_budget = 96
    if len(header) + trailer_budget > limit:
        raise ValueError("metadata exceeds the evidence byte limit")
    kept: list[bytes] = []
    used = len(header)
    for record in records:
        entry = encode(record)
        if used + bool(kept) + len(entry) + trailer_budget > limit:
            break
        used += bool(kept) + len(entry)
        kept.append(entry)
    omitted = len(records) - len(kept)
    receipt = {"truncated": bool(omitted), "findings_omitted": omitted,
               "complete": report["status"] == "complete" and not omitted}
    trailer = b"]," + encode(receipt)[1:] + b"\n"
    # Create a new protected leaf. Require an existing user-controlled parent.
    path.mkdir(mode=0o700)
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise PermissionError("filesystem did not apply private directory permissions")
    fd, temporary = tempfile.mkstemp(dir=path)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(header + b",".join(kept) + trailer)
        os.replace(temporary, path / "findings.json")
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"written": True, "findings_saved": len(kept), "findings_omitted": omitted, "truncated": bool(omitted)}


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    aws = shutil.which("aws")
    if os.name == "nt" and aws and Path(aws).suffix.lower() != ".exe":
        aws = None
    report, records = build_report(args, aws)
    if args.evidence_dir and report["coverage"]["identity_verified"]:
        try:
            report["evidence"] = save_evidence(args.evidence_dir, report, records, args.max_output_bytes)
        except OSError:
            report["blockers"].append({"scope": "evidence", "reason": "protected_evidence_write_failed"})
        except ValueError:
            report["blockers"].append({"scope": "evidence", "reason": "evidence_metadata_byte_limit"})
        else:
            if report["evidence"]["truncated"]:
                report["blockers"].append({"scope": "evidence", "reason": "evidence_byte_limit"})
    if len(result_payload(report)[0].replace("\n", os.linesep).encode("utf-8")) > args.max_output_bytes:
        # Keep a compact coverage receipt when even the normal summary exceeds the limit.
        report["summary"]["services"] = {
            name: {key: status[key] for key in ("outcome", "complete", "truncated", "findings_collected")}
            for name, status in report["summary"]["services"].items()
        }
        report["coverage"]["truncated"] = True
        report["blockers"].append({"scope": "summary", "reason": "summary_byte_limit"})
    return emit_result(report, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
