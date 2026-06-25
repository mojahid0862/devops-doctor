#!/usr/bin/env python3
"""Bounded read-only AWS stack snapshot for DevOps Doctor."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


DEFAULT_SERVICES = ["ecs", "rds", "elasticache", "s3", "cloudfront", "route53", "lambda", "cloudwatch", "ecr", "cloudtrail"]
SECRET_PATTERNS = [
    (re.compile(r"(?i)(token|password|passwd|secret|key)(\s*[:=]\s*)([^\s\"']+)"), r"\1\2[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_ACCESS_KEY_ID]"),
    (re.compile(r"(?i)aws_secret_access_key\s*=\s*[^\s]+"), "aws_secret_access_key=[REDACTED]"),
]


def redact(text: str) -> str:
    cleaned = text
    for pattern, replacement in SECRET_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def scoped(base: list[str], profile: str | None, region: str | None) -> list[str]:
    command = ["aws", *base]
    if profile:
        command.extend(["--profile", profile])
    if region:
        command.extend(["--region", region])
    return command


def run(command: list[str], *, timeout: int = 60, parse_json: bool = True) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "command": " ".join(command)}

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    result: dict[str, Any] = {"ok": completed.returncode == 0, "command": " ".join(command)}
    if completed.returncode != 0:
        result["error"] = redact(stderr or stdout)[-2000:]
        return result
    if parse_json:
        try:
            result["data"] = json.loads(stdout) if stdout else None
        except json.JSONDecodeError:
            result["data"] = redact(stdout)[-4000:]
    else:
        result["data"] = redact(stdout)[-12000:]
    return result


def aws_json(base: list[str], profile: str | None, region: str | None, timeout: int = 60) -> dict[str, Any]:
    return run([*scoped(base, profile, region), "--output", "json"], timeout=timeout)


def since_to_start(value: str) -> str:
    match = re.fullmatch(r"(\d+)([hmHdD])", value.strip())
    if not match:
        return value
    amount = int(match.group(1))
    unit = match.group(2).lower()
    delta = timedelta(hours=amount) if unit == "h" else timedelta(minutes=amount) if unit == "m" else timedelta(days=amount)
    return (datetime.now(timezone.utc) - delta).isoformat()


def collect_ecs(args: argparse.Namespace) -> dict[str, Any]:
    if args.cluster and args.service:
        service = aws_json(
            [
                "ecs",
                "describe-services",
                "--cluster",
                args.cluster,
                "--services",
                args.service,
                "--query",
                "services[].{serviceName:serviceName,status:status,desiredCount:desiredCount,runningCount:runningCount,pendingCount:pendingCount,taskDefinition:taskDefinition,deployments:deployments,events:events[0:10],loadBalancers:loadBalancers,capacityProviderStrategy:capacityProviderStrategy,networkConfiguration:networkConfiguration}",
            ],
            args.profile,
            args.region,
        )
        stopped = aws_json(
            ["ecs", "list-tasks", "--cluster", args.cluster, "--service-name", args.service, "--desired-status", "STOPPED", "--max-results", "10"],
            args.profile,
            args.region,
        )
        running = aws_json(
            ["ecs", "list-tasks", "--cluster", args.cluster, "--service-name", args.service, "--desired-status", "RUNNING", "--max-results", "10"],
            args.profile,
            args.region,
        )
        return {"service": service, "stopped_tasks": stopped, "running_tasks": running}

    clusters = aws_json(["ecs", "list-clusters"], args.profile, args.region)
    cluster_arns = clusters.get("data", {}).get("clusterArns", []) if clusters.get("ok") else []
    services: list[dict[str, Any]] = []
    for cluster in cluster_arns[:10]:
        listed = aws_json(["ecs", "list-services", "--cluster", cluster, "--max-results", "25"], args.profile, args.region)
        service_arns = listed.get("data", {}).get("serviceArns", []) if listed.get("ok") else []
        if service_arns:
            services.append(
                {
                    "cluster": cluster,
                    "services": aws_json(
                        [
                            "ecs",
                            "describe-services",
                            "--cluster",
                            cluster,
                            "--services",
                            *service_arns[:10],
                            "--query",
                            "services[].{serviceName:serviceName,status:status,desiredCount:desiredCount,runningCount:runningCount,pendingCount:pendingCount,taskDefinition:taskDefinition,deployments:deployments[0:2],events:events[0:3],loadBalancers:loadBalancers}",
                        ],
                        args.profile,
                        args.region,
                    ),
                }
            )
    return {"clusters": clusters, "services": services}


def collect_rds(args: argparse.Namespace) -> dict[str, Any]:
    query = "DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,DBInstanceClass:DBInstanceClass,Engine:Engine,EngineVersion:EngineVersion,DBInstanceStatus:DBInstanceStatus,AllocatedStorage:AllocatedStorage,StorageType:StorageType,MultiAZ:MultiAZ,PubliclyAccessible:PubliclyAccessible,StorageEncrypted:StorageEncrypted,BackupRetentionPeriod:BackupRetentionPeriod,DeletionProtection:DeletionProtection,VpcSecurityGroups:VpcSecurityGroups[].VpcSecurityGroupId}"
    instances = aws_json(["rds", "describe-db-instances", "--query", query], args.profile, args.region)
    clusters = aws_json(
        [
            "rds",
            "describe-db-clusters",
            "--query",
            "DBClusters[].{DBClusterIdentifier:DBClusterIdentifier,Engine:Engine,EngineVersion:EngineVersion,Status:Status,StorageEncrypted:StorageEncrypted,BackupRetentionPeriod:BackupRetentionPeriod,DeletionProtection:DeletionProtection,DBClusterMembers:DBClusterMembers[].DBInstanceIdentifier}",
        ],
        args.profile,
        args.region,
    )
    return {"instances": instances, "clusters": clusters, "filter": args.db}


def collect_elasticache(args: argparse.Namespace) -> dict[str, Any]:
    clusters = aws_json(
        [
            "elasticache",
            "describe-cache-clusters",
            "--show-cache-node-info",
            "--query",
            "CacheClusters[].{CacheClusterId:CacheClusterId,Engine:Engine,CacheClusterStatus:CacheClusterStatus,CacheNodeType:CacheNodeType,NumCacheNodes:NumCacheNodes,TransitEncryptionEnabled:TransitEncryptionEnabled,AtRestEncryptionEnabled:AtRestEncryptionEnabled,CacheSubnetGroupName:CacheSubnetGroupName,SecurityGroups:SecurityGroups[].SecurityGroupId}",
        ],
        args.profile,
        args.region,
    )
    repl = aws_json(
        [
            "elasticache",
            "describe-replication-groups",
            "--query",
            "ReplicationGroups[].{ReplicationGroupId:ReplicationGroupId,Status:Status,Engine:Engine,MultiAZ:MultiAZ,AutomaticFailover:AutomaticFailover,TransitEncryptionEnabled:TransitEncryptionEnabled,AtRestEncryptionEnabled:AtRestEncryptionEnabled,CacheNodeType:CacheNodeType}",
        ],
        args.profile,
        args.region,
    )
    return {"cache_clusters": clusters, "replication_groups": repl, "filter": args.cache}


def collect_s3(args: argparse.Namespace) -> dict[str, Any]:
    buckets = aws_json(["s3api", "list-buckets", "--query", "Buckets[].Name"], args.profile, None)
    bucket_names = buckets.get("data", []) if buckets.get("ok") and isinstance(buckets.get("data"), list) else []
    details = []
    for name in bucket_names[:50]:
        details.append(
            {
                "name": name,
                "location": aws_json(["s3api", "get-bucket-location", "--bucket", name], args.profile, None, timeout=30),
                "public_access_block": aws_json(["s3api", "get-public-access-block", "--bucket", name], args.profile, None, timeout=30),
                "encryption": aws_json(["s3api", "get-bucket-encryption", "--bucket", name], args.profile, None, timeout=30),
            }
        )
    return {"buckets": buckets, "bucket_details": details}


def collect_cloudfront(args: argparse.Namespace) -> dict[str, Any]:
    if args.distribution_id:
        return {"distribution": aws_json(["cloudfront", "get-distribution", "--id", args.distribution_id], args.profile, None)}
    return {
        "distributions": aws_json(
            [
                "cloudfront",
                "list-distributions",
                "--query",
                "DistributionList.Items[].{Id:Id,DomainName:DomainName,Enabled:Enabled,Status:Status,PriceClass:PriceClass,Aliases:Aliases.Items,Origins:Origins.Items[].DomainName,ViewerCertificate:ViewerCertificate.CloudFrontDefaultCertificate}",
            ],
            args.profile,
            None,
        )
    }


def collect_route53(args: argparse.Namespace) -> dict[str, Any]:
    if args.hosted_zone_id:
        return {
            "hosted_zone": aws_json(["route53", "get-hosted-zone", "--id", args.hosted_zone_id], args.profile, None),
            "records": aws_json(["route53", "list-resource-record-sets", "--hosted-zone-id", args.hosted_zone_id, "--max-items", "50"], args.profile, None),
        }
    return {"hosted_zones": aws_json(["route53", "list-hosted-zones"], args.profile, None)}


def collect_lambda(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "functions": aws_json(
            [
                "lambda",
                "list-functions",
                "--query",
                "Functions[].{FunctionName:FunctionName,Runtime:Runtime,MemorySize:MemorySize,Timeout:Timeout,LastModified:LastModified,PackageType:PackageType,State:State,Architectures:Architectures}",
            ],
            args.profile,
            args.region,
        )
    }


def collect_cloudwatch(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "alarms": aws_json(
            [
                "cloudwatch",
                "describe-alarms",
                "--state-value",
                "ALARM",
                "--query",
                "MetricAlarms[].{AlarmName:AlarmName,StateValue:StateValue,StateReason:StateReason,Namespace:Namespace,MetricName:MetricName,Dimensions:Dimensions,UpdatedTimestamp:StateUpdatedTimestamp}",
            ],
            args.profile,
            args.region,
        )
    }


def collect_ecr(args: argparse.Namespace) -> dict[str, Any]:
    repos = aws_json(
        [
            "ecr",
            "describe-repositories",
            "--query",
            "repositories[].{repositoryName:repositoryName,repositoryUri:repositoryUri,imageScanningConfiguration:imageScanningConfiguration,createdAt:createdAt}",
        ],
        args.profile,
        args.region,
    )
    return {"repositories": repos}


def collect_cloudtrail(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "events": aws_json(
            [
                "cloudtrail",
                "lookup-events",
                "--start-time",
                since_to_start(args.since),
                "--max-results",
                "50",
                "--query",
                "Events[].{EventTime:EventTime,EventName:EventName,Username:Username,EventSource:EventSource,ResourceName:Resources[0].ResourceName}",
            ],
            args.profile,
            args.region,
        )
    }


COLLECTORS = {
    "ecs": collect_ecs,
    "rds": collect_rds,
    "elasticache": collect_elasticache,
    "s3": collect_s3,
    "cloudfront": collect_cloudfront,
    "route53": collect_route53,
    "lambda": collect_lambda,
    "cloudwatch": collect_cloudwatch,
    "ecr": collect_ecr,
    "cloudtrail": collect_cloudtrail,
}


def summarize_and_findings(raw_services: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    summary: dict[str, Any] = {"services_collected": sorted(raw_services.keys())}
    findings: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []

    def inspect_result(scope: str, result: Any) -> None:
        if isinstance(result, dict) and "ok" in result and not result.get("ok"):
            blockers.append({"scope": scope, "reason": result.get("error", "command failed")})
        elif isinstance(result, dict):
            for key, value in result.items():
                inspect_result(f"{scope}.{key}", value)
        elif isinstance(result, list):
            for index, item in enumerate(result):
                inspect_result(f"{scope}[{index}]", item)

    inspect_result("services", raw_services)

    ecs_data = raw_services.get("ecs", {})
    ecs_items = ecs_data.get("services", [])
    if not ecs_items and isinstance(ecs_data.get("service"), dict):
        ecs_items = [{"services": ecs_data.get("service")}]
    unhealthy = 0
    for group in ecs_items if isinstance(ecs_items, list) else []:
        data = group.get("services", {}).get("data", [])
        for svc in data if isinstance(data, list) else []:
            if svc.get("desiredCount") != svc.get("runningCount") or svc.get("pendingCount"):
                unhealthy += 1
                findings.append({"severity": "high", "service": "ecs", "rule": "desired_running_mismatch", "resource": svc.get("serviceName")})
    summary["ecs_unhealthy_services"] = unhealthy

    rds_instances = raw_services.get("rds", {}).get("instances", {}).get("data", [])
    for db in rds_instances if isinstance(rds_instances, list) else []:
        if db.get("PubliclyAccessible"):
            findings.append({"severity": "high", "service": "rds", "rule": "publicly_accessible", "resource": db.get("DBInstanceIdentifier")})
        if not db.get("StorageEncrypted"):
            findings.append({"severity": "high", "service": "rds", "rule": "storage_not_encrypted", "resource": db.get("DBInstanceIdentifier")})
        if not db.get("DeletionProtection"):
            findings.append({"severity": "medium", "service": "rds", "rule": "deletion_protection_disabled", "resource": db.get("DBInstanceIdentifier")})

    alarms = raw_services.get("cloudwatch", {}).get("alarms", {}).get("data", [])
    if isinstance(alarms, list):
        summary["cloudwatch_alarm_count"] = len(alarms)
        for alarm in alarms[:10]:
            findings.append({"severity": "medium", "service": "cloudwatch", "rule": "alarm_in_alarm_state", "resource": alarm.get("AlarmName")})

    cache_groups = raw_services.get("elasticache", {}).get("replication_groups", {}).get("data", [])
    for cache in cache_groups if isinstance(cache_groups, list) else []:
        if cache.get("TransitEncryptionEnabled") is False:
            findings.append({"severity": "medium", "service": "elasticache", "rule": "transit_encryption_disabled", "resource": cache.get("ReplicationGroupId")})
        if cache.get("AtRestEncryptionEnabled") is False:
            findings.append({"severity": "medium", "service": "elasticache", "rule": "at_rest_encryption_disabled", "resource": cache.get("ReplicationGroupId")})

    return summary, findings, blockers


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect a bounded read-only AWS stack snapshot.")
    parser.add_argument("--profile", help="AWS profile.")
    parser.add_argument("--region", required=True, help="AWS region.")
    parser.add_argument("--services", default=",".join(DEFAULT_SERVICES), help=f"Comma-separated services: {','.join(DEFAULT_SERVICES)}.")
    parser.add_argument("--cluster", help="ECS cluster name or ARN.")
    parser.add_argument("--service", help="ECS service name.")
    parser.add_argument("--db", help="Optional RDS DB identifier hint.")
    parser.add_argument("--cache", help="Optional ElastiCache identifier hint.")
    parser.add_argument("--distribution-id", help="CloudFront distribution ID.")
    parser.add_argument("--hosted-zone-id", help="Route 53 hosted zone ID.")
    parser.add_argument("--since", default="2h", help="CloudTrail lookback, for example 2h or 1d.")
    parser.add_argument("--output", help="Write JSON snapshot to this path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not shutil.which("aws"):
        print("aws CLI not found in PATH.", file=sys.stderr)
        return 2

    selected = [service.strip().lower() for service in args.services.split(",") if service.strip()]
    unknown = sorted(set(selected) - set(COLLECTORS))
    if unknown:
        print(f"Unsupported services: {', '.join(unknown)}", file=sys.stderr)
        return 2

    raw_services: dict[str, Any] = {}
    for service in selected:
        raw_services[service] = COLLECTORS[service](args)

    summary, findings, blockers = summarize_and_findings(raw_services)
    result = {
        "summary": {
            **summary,
            "profile": args.profile,
            "region": args.region,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "findings": findings,
        "evidence": {
            "identity": aws_json(["sts", "get-caller-identity"], args.profile, None),
            "filters": {
                "cluster": args.cluster,
                "service": args.service,
                "db": args.db,
                "cache": args.cache,
                "distribution_id": args.distribution_id,
                "hosted_zone_id": args.hosted_zone_id,
                "since": args.since,
            },
        },
        "blockers": blockers,
        "next_commands": [
            "aws cloudwatch describe-alarms --state-value ALARM",
            "aws ecs describe-services --cluster <cluster> --services <service>",
        ],
        "raw": {"services": raw_services},
    }

    payload = json.dumps(result, indent=2, sort_keys=True, default=str)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
