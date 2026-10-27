#!/usr/bin/env python3
"""Bounded read-only AWS stack snapshot for DevOps Doctor."""

from __future__ import annotations

import argparse
import re
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

from doctor_common import collect_status, emit_result, run_command


DEFAULT_SERVICES = ["ecs", "rds", "elasticache", "s3", "cloudfront", "route53", "lambda", "cloudwatch", "ecr", "cloudtrail"]
def scoped(base: list[str], profile: str | None, region: str | None) -> list[str]:
    command = ["aws", *base]
    if profile:
        command.extend(["--profile", profile])
    if region:
        command.extend(["--region", region])
    return command


def run(command: list[str], *, timeout: int = 60, parse_json: bool = True) -> dict[str, Any]:
    return run_command(command, timeout=timeout, parse_json=parse_json)


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
    query = "{services:services[].{serviceName:serviceName,status:status,desiredCount:desiredCount,runningCount:runningCount,pendingCount:pendingCount,taskDefinition:taskDefinition,deployments:deployments[0:2],events:events[0:10],loadBalancers:loadBalancers},failures:failures}"

    def describe(cluster: str, services: list[str]) -> dict[str, Any]:
        result = aws_json(["ecs", "describe-services", "--cluster", cluster, "--services", *services, "--query", query], args.profile, args.region)
        data = result.get("data")
        if result.get("ok") and isinstance(data, dict):
            result = {**result, "data": data.get("services", [])}
            if data.get("failures"):
                result.update(ok=False, error="ECS describe-services returned resource failures", api_failures=data["failures"])
        return result

    if args.cluster and args.service:
        service = describe(args.cluster, [args.service])
        tasks = {}
        for state in ("STOPPED", "RUNNING"):
            tasks[state.lower() + "_tasks"] = aws_json(
                ["ecs", "list-tasks", "--cluster", args.cluster, "--service-name", args.service,
                 "--desired-status", state, "--max-items", "10"], args.profile, args.region)
        return {"service": service, **tasks}

    clusters = ({"ok": True, "data": {"clusterArns": [args.cluster]}} if args.cluster else
                aws_json(["ecs", "list-clusters", "--max-items", "11"], args.profile, args.region))
    data = clusters.get("data")
    cluster_arns = data.get("clusterArns", []) if clusters.get("ok") and isinstance(data, dict) else []
    truncated = len(cluster_arns) > 10 or bool(isinstance(data, dict) and data.get("NextToken"))
    services = []
    for cluster in cluster_arns[:10]:
        listed = aws_json(["ecs", "list-services", "--cluster", cluster, "--max-items", "11"], args.profile, args.region)
        data = listed.get("data")
        service_arns = data.get("serviceArns", []) if listed.get("ok") and isinstance(data, dict) else []
        omitted = len(service_arns) > 10 or bool(isinstance(data, dict) and data.get("NextToken"))
        truncated = truncated or omitted
        group = {"cluster": cluster, "listed": listed, "coverage": {"limit": 10, "inspected": min(10, len(service_arns)), "truncated": omitted}}
        if service_arns:
            group["services"] = describe(cluster, service_arns[:10])
        services.append(group)
    return {"clusters": clusters, "services": services,
            "coverage": {"cluster_limit": 10, "clusters_inspected": min(10, len(cluster_arns)), "truncated": truncated}}


def collect_rds(args: argparse.Namespace) -> dict[str, Any]:
    query = "DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,DBInstanceClass:DBInstanceClass,Engine:Engine,EngineVersion:EngineVersion,DBInstanceStatus:DBInstanceStatus,AllocatedStorage:AllocatedStorage,StorageType:StorageType,MultiAZ:MultiAZ,PubliclyAccessible:PubliclyAccessible,StorageEncrypted:StorageEncrypted,BackupRetentionPeriod:BackupRetentionPeriod,DeletionProtection:DeletionProtection,VpcSecurityGroups:VpcSecurityGroups[].VpcSecurityGroupId}"
    instance_args = ["rds", "describe-db-instances", "--query", query]
    if args.db:
        instance_args += ["--db-instance-identifier", args.db]
    instances = aws_json(instance_args, args.profile, args.region)
    if args.db:
        return {"instances": instances, "filter": args.db,
                "coverage": {"scope": "db_instance", "identifier": args.db, "truncated": False}}
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
            *(["--cache-cluster-id", args.cache] if args.cache else []),
        ],
        args.profile,
        args.region,
    )
    if args.cache:
        return {"cache_clusters": clusters, "filter": args.cache,
                "coverage": {"scope": "cache_cluster", "identifier": args.cache, "truncated": False}}
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
    limit = args.max_buckets
    buckets = aws_json(["s3api", "list-buckets", "--max-items", str(limit + 1)], args.profile, None)
    data = buckets.get("data") if buckets.get("ok") else {}
    bucket_names = [item["Name"] for item in data.get("Buckets", []) if item.get("Name")] if isinstance(data, dict) else []
    truncated = bool(isinstance(data, dict) and (data.get("NextToken") or data.get("ContinuationToken"))) or len(bucket_names) > limit
    details = []
    for name in bucket_names[:limit]:
        details.append(
            {
                "name": name,
                "location": aws_json(["s3api", "get-bucket-location", "--bucket", name], args.profile, None, timeout=30),
                "public_access_block": aws_json(["s3api", "get-public-access-block", "--bucket", name], args.profile, None, timeout=30),
                "encryption": aws_json(["s3api", "get-bucket-encryption", "--bucket", name], args.profile, None, timeout=30),
            }
        )
    return {"buckets": buckets, "bucket_details": details,
            "coverage": {"limit": limit, "discovered": len(bucket_names), "inspected": len(details),
                         "total_known": None if truncated or not buckets.get("ok") else len(bucket_names), "truncated": truncated}}


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
                "--max-items",
                "50",
                "--query",
                "{Events:Events[].{EventTime:EventTime,EventName:EventName,Username:Username,EventSource:EventSource,ResourceName:Resources[0].ResourceName},NextToken:NextToken}",
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
    evaluated = 0
    for group in ecs_items if isinstance(ecs_items, list) else []:
        data = group.get("services", {}).get("data", [])
        for svc in data if isinstance(data, list) else []:
            evaluated += 1
            if svc.get("desiredCount") != svc.get("runningCount") or svc.get("pendingCount"):
                unhealthy += 1
                findings.append({"severity": "high", "service": "ecs", "rule": "desired_running_mismatch", "resource": svc.get("serviceName")})
    ecs_complete = "ecs" in raw_services and not any(item["scope"].startswith("services.ecs") for item in blockers)
    summary["ecs_unhealthy_services"] = unhealthy if ecs_complete or evaluated else None
    summary["ecs_evaluated_services"] = evaluated if "ecs" in raw_services else None

    rds_instances = raw_services.get("rds", {}).get("instances", {}).get("data", [])
    for db in rds_instances if isinstance(rds_instances, list) else []:
        if db.get("PubliclyAccessible"):
            findings.append({"severity": "high", "service": "rds", "rule": "publicly_accessible", "resource": db.get("DBInstanceIdentifier")})
        if db.get("StorageEncrypted") is False:
            findings.append({"severity": "high", "service": "rds", "rule": "storage_not_encrypted", "resource": db.get("DBInstanceIdentifier")})
        if db.get("DeletionProtection") is False:
            findings.append({"severity": "medium", "service": "rds", "rule": "deletion_protection_disabled", "resource": db.get("DBInstanceIdentifier")})

    alarm_result = raw_services.get("cloudwatch", {}).get("alarms", {})
    alarms = alarm_result.get("data")
    if alarm_result.get("ok") and isinstance(alarms, list):
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


def bounded_int(minimum: int, maximum: int):
    def parse(value: str) -> int:
        try:
            number = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("expected an integer") from exc
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f"must be between {minimum} and {maximum}")
        return number
    return parse


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect a bounded read-only AWS stack snapshot.")
    parser.add_argument("--profile", help="AWS profile.")
    parser.add_argument("--region", required=True, help="AWS region.")
    parser.add_argument("--services", default=",".join(DEFAULT_SERVICES), help=f"Comma-separated services: {','.join(DEFAULT_SERVICES)}.")
    parser.add_argument("--cluster", help="ECS cluster name or ARN.")
    parser.add_argument("--service", help="ECS service name; requires --cluster.")
    parser.add_argument("--db", help="Exact RDS DB instance identifier; skips unrelated cluster inventory.")
    parser.add_argument("--cache", help="Exact ElastiCache cache cluster identifier; skips unrelated replication groups.")
    parser.add_argument("--distribution-id", help="CloudFront distribution ID.")
    parser.add_argument("--hosted-zone-id", help="Route 53 hosted zone ID.")
    parser.add_argument("--since", default="2h", help="CloudTrail lookback, for example 2h or 1d.")
    parser.add_argument("--max-workers", type=bounded_int(1, 16), default=4, help="Maximum concurrent service collectors (1-16; default 4).")
    parser.add_argument("--max-buckets", type=bounded_int(1, 1000), default=20, help="Maximum S3 buckets inspected (1-1000; default 20).")
    parser.add_argument("--output", help="Write JSON snapshot to this path.")
    args = parser.parse_args(argv)
    args.selected_services = list(dict.fromkeys(service.strip().lower() for service in args.services.split(",") if service.strip()))
    unknown = sorted(set(args.selected_services) - set(COLLECTORS))
    if not args.selected_services or unknown:
        parser.error("--services must contain supported services" + (f": {', '.join(unknown)}" if unknown else ""))
    if args.service and not args.cluster:
        parser.error("--service requires --cluster")
    return args


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    selected = args.selected_services
    identity = aws_json(["sts", "get-caller-identity"], args.profile, args.region)
    identity_data = identity.get("data")
    if identity.get("ok") and (not isinstance(identity_data, dict) or not identity_data.get("Account")):
        identity = {**identity, "ok": False, "error": "STS response lacks Account"}
    filters = {key: getattr(args, key) for key in ("cluster", "service", "db", "cache", "distribution_id", "hosted_zone_id", "since")}
    scope = {"account_id": identity_data.get("Account") if isinstance(identity_data, dict) else None,
             "region": args.region, "collector": "aws_stack_snapshot",
             "filters": {**filters, "services": sorted(selected),
                         "limits": {"max_buckets": args.max_buckets, "max_ecs_clusters": 10,
                                    "max_ecs_services_per_cluster": 10, "max_tasks_per_state": 10,
                                    "max_cloudtrail_events": 50, "max_route53_records": 50}}}
    result = {
        "summary": {"profile": args.profile, "region": args.region, "generated_at": datetime.now(timezone.utc).isoformat()},
        "scope": scope, "findings": [], "evidence": {"identity": identity, "filters": filters},
        "blockers": [], "next_commands": [], "raw": {"services": {}},
    }
    if not identity.get("ok"):
        result.update(status="failed", collection={"complete": False})
        result["blockers"] = [{"scope": "identity", "reason": identity.get("error", "authentication failed")}]
        return result

    def collect(name: str) -> dict[str, Any]:
        try:
            return COLLECTORS[name](args)
        except Exception as exc:
            return {"ok": False, "error": f"collector failed: {type(exc).__name__}: {exc}"}

    with ThreadPoolExecutor(max_workers=min(args.max_workers, len(selected))) as pool:
        futures = {name: pool.submit(collect, name) for name in selected}
        raw_services = {name: future.result() for name, future in futures.items()}
    summary, findings, blockers = summarize_and_findings(raw_services)
    result["summary"].update(summary)
    result["findings"] = findings
    result["blockers"] = blockers
    result["raw"]["services"] = raw_services
    # Authentication success is not evidence that a failed service collection succeeded.
    result["status"] = collect_status({"raw": raw_services, "blockers": blockers})
    result["collection"] = {"complete": result["status"] == "complete",
                            "requested_services": selected, "max_workers": args.max_workers}
    return result


def main() -> int:
    args = parse_args()
    if not shutil.which("aws"):
        return emit_result({"status": "failed", "collection": {"complete": False},
                            "blockers": [{"scope": "aws", "reason": "aws CLI not found in PATH"}]}, args.output)
    return emit_result(build_report(args), args.output)


if __name__ == "__main__":
    raise SystemExit(main())
