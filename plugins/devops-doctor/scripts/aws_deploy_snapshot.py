#!/usr/bin/env python3
"""Collect bounded read-only AWS deployment evidence."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


SECRET_PATTERNS = [
    (re.compile(r"(?i)(token|password|passwd|secret|key)(\s*[:=]\s*)([^\s\"']+)"), r"\1\2[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_ACCESS_KEY_ID]"),
    (re.compile(r"(?i)aws_secret_access_key\s*=\s*[^\s]+"), "aws_secret_access_key=[REDACTED]"),
]

THROTTLING_NOTE = "Lower --max-workers if AWS API throttling appears."

RDS_METRICS = [
    "CPUUtilization",
    "DatabaseConnections",
    "FreeableMemory",
    "FreeStorageSpace",
    "ReadLatency",
    "WriteLatency",
]


def redact(text: str) -> str:
    cleaned = text
    for pattern, replacement in SECRET_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def command_text(command: list[str]) -> str:
    return " ".join(command)


def scoped(base: list[str], profile: str | None, region: str | None) -> list[str]:
    command = ["aws", *base]
    if profile:
        command.extend(["--profile", profile])
    if region:
        command.extend(["--region", region])
    return command


def run(command: list[str], *, timeout: int = 60, parse_json: bool = True) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "command": command_text(command)}

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    result: dict[str, Any] = {"ok": completed.returncode == 0, "command": command_text(command)}
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


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def run_tier(executor: ThreadPoolExecutor, tasks: dict[str, Callable[[], Any]]) -> dict[str, Any]:
    futures: dict[Future[Any], str] = {executor.submit(task): key for key, task in tasks.items()}
    results: dict[str, Any] = {}
    for future in as_completed(futures):
        key = futures[future]
        try:
            results[key] = future.result()
        except Exception as exc:  # Defensive: keep snapshot JSON complete on local orchestration errors.
            results[key] = {"ok": False, "error": redact(str(exc)), "command": "internal"}
    return results


def since_to_start(value: str) -> str:
    match = re.fullmatch(r"(\d+)([hmHdD])", value.strip())
    if not match:
        return value
    amount = int(match.group(1))
    unit = match.group(2).lower()
    if unit == "m":
        delta = timedelta(minutes=amount)
    elif unit == "h":
        delta = timedelta(hours=amount)
    else:
        delta = timedelta(days=amount)
    return (datetime.now(timezone.utc) - delta).isoformat()


def parse_ecr_image(image: str) -> dict[str, str] | None:
    match = re.match(r"(?P<account>\d+)\.dkr\.ecr\.(?P<region>[^.]+)\.amazonaws\.com/(?P<repo>[^@:]+)(?::(?P<tag>[^@]+))?(?:@(?P<digest>sha256:[a-f0-9]+))?", image)
    if not match:
        return None
    return {key: value for key, value in match.groupdict().items() if value}


def metric_window(minutes: int = 30) -> tuple[str, str]:
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(minutes=minutes)
    return start.isoformat(), end.isoformat()


def collect_cloudwatch_metrics(
    namespace: str,
    dimensions: dict[str, str],
    metrics: list[str],
    profile: str | None,
    region: str | None,
    *,
    minutes: int = 30,
    period: int = 60,
) -> dict[str, Any]:
    start, end = metric_window(minutes)
    dimension_args = [f"Name={name},Value={value}" for name, value in dimensions.items()]
    return {
        "namespace": namespace,
        "dimensions": dimensions,
        "window_minutes": minutes,
        "period_seconds": period,
        "metrics": {
            metric: aws_json(
                [
                    "cloudwatch",
                    "get-metric-statistics",
                    "--namespace",
                    namespace,
                    "--metric-name",
                    metric,
                    "--dimensions",
                    *dimension_args,
                    "--start-time",
                    start,
                    "--end-time",
                    end,
                    "--period",
                    str(period),
                    "--statistics",
                    "Average",
                    "Maximum",
                    "--query",
                    "Datapoints[].{Timestamp:Timestamp,Average:Average,Maximum:Maximum,Unit:Unit}",
                ],
                profile,
                region,
                timeout=45,
            )
            for metric in metrics
        },
    }


def collect_rds_db_instance(identifier: str, profile: str | None, region: str | None) -> dict[str, Any]:
    return {
        "db_instance_identifier": identifier,
        "status": aws_json(
            [
                "rds",
                "describe-db-instances",
                "--db-instance-identifier",
                identifier,
                "--query",
                "DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,DBInstanceStatus:DBInstanceStatus,Engine:Engine,EngineVersion:EngineVersion,DBInstanceClass:DBInstanceClass,MultiAZ:MultiAZ,PubliclyAccessible:PubliclyAccessible,StorageEncrypted:StorageEncrypted,AllocatedStorage:AllocatedStorage,Endpoint:Endpoint.Address,LatestRestorableTime:LatestRestorableTime,PendingModifiedValues:PendingModifiedValues}",
            ],
            profile,
            region,
        ),
        "cloudwatch_metrics": collect_cloudwatch_metrics(
            "AWS/RDS",
            {"DBInstanceIdentifier": identifier},
            RDS_METRICS,
            profile,
            region,
        ),
    }


def collect_elasticache_cache_cluster(cluster_id: str, profile: str | None, region: str | None) -> dict[str, Any]:
    return aws_json(
        [
            "elasticache",
            "describe-cache-clusters",
            "--cache-cluster-id",
            cluster_id,
            "--show-cache-node-info",
            "--query",
            "CacheClusters[].{CacheClusterId:CacheClusterId,Engine:Engine,CacheClusterStatus:CacheClusterStatus,NumCacheNodes:NumCacheNodes,PreferredAvailabilityZone:PreferredAvailabilityZone,CacheNodeType:CacheNodeType,CacheNodes:CacheNodes[].{CacheNodeId:CacheNodeId,CacheNodeStatus:CacheNodeStatus,Endpoint:Endpoint.Address},SecurityGroups:SecurityGroups,VpcSecurityGroups:VpcSecurityGroups}",
        ],
        profile,
        region,
    )


def collect_elasticache_replication_group(replication_group_id: str, profile: str | None, region: str | None) -> dict[str, Any]:
    return aws_json(
        [
            "elasticache",
            "describe-replication-groups",
            "--replication-group-id",
            replication_group_id,
            "--query",
            "ReplicationGroups[].{ReplicationGroupId:ReplicationGroupId,Status:Status,Description:Description,AutomaticFailover:AutomaticFailover,MultiAZ:MultiAZ,AtRestEncryptionEnabled:AtRestEncryptionEnabled,TransitEncryptionEnabled:TransitEncryptionEnabled,NodeGroups:NodeGroups[].{Status:Status,PrimaryEndpoint:PrimaryEndpoint.Address,ReaderEndpoint:ReaderEndpoint.Address,NodeGroupMembers:NodeGroupMembers[].{CacheClusterId:CacheClusterId,CurrentRole:CurrentRole,PreferredAvailabilityZone:PreferredAvailabilityZone}}}",
        ],
        profile,
        region,
    )


def collect_cloudfront_distribution(distribution_id: str, profile: str | None) -> dict[str, Any]:
    return aws_json(
        [
            "cloudfront",
            "get-distribution",
            "--id",
            distribution_id,
            "--query",
            "Distribution.{Id:Id,ARN:ARN,Status:Status,DomainName:DomainName,Enabled:DistributionConfig.Enabled,LastModifiedTime:LastModifiedTime,DefaultRootObject:DistributionConfig.DefaultRootObject,Origins:DistributionConfig.Origins.Items[].{Id:Id,DomainName:DomainName},Aliases:DistributionConfig.Aliases.Items}",
        ],
        profile,
        None,
    )


def collect_route53_hosted_zone(hosted_zone_id: str, profile: str | None) -> dict[str, Any]:
    return aws_json(
        [
            "route53",
            "get-hosted-zone",
            "--id",
            hosted_zone_id,
            "--query",
            "{HostedZone:HostedZone,DelegationSet:DelegationSet,VPCs:VPCs}",
        ],
        profile,
        None,
    )


def collect_route53_health_check_status(health_check_id: str, profile: str | None) -> dict[str, Any]:
    return aws_json(
        ["route53", "get-health-check-status", "--health-check-id", health_check_id],
        profile,
        None,
    )


def collect_ecr_images(task_definition: dict[str, Any], profile: str | None, region: str | None) -> list[dict[str, Any]]:
    data = task_definition.get("data") if task_definition.get("ok") else None
    containers = data.get("containerDefinitions", []) if isinstance(data, dict) else []
    images: list[dict[str, Any]] = []
    for container in containers:
        image = container.get("image")
        parsed = parse_ecr_image(str(image or ""))
        if not parsed:
            continue
        selector = ["--image-ids"]
        if parsed.get("digest"):
            selector.extend(["imageDigest=" + parsed["digest"]])
        elif parsed.get("tag"):
            selector.extend(["imageTag=" + parsed["tag"]])
        else:
            selector = []
        images.append(
            {
                "container": container.get("name"),
                "image": image,
                "repository": parsed.get("repo"),
                "details": aws_json(["ecr", "describe-images", "--repository-name", parsed["repo"], *selector], profile, parsed.get("region") or region, timeout=45),
            }
        )
    return images


def stopped_task_arns(stopped_tasks: Any) -> list[str]:
    if not isinstance(stopped_tasks, dict) or not stopped_tasks.get("ok"):
        return []
    data = stopped_tasks.get("data")
    if not isinstance(data, dict):
        return []
    task_arns = data.get("taskArns", [])
    return [str(task_arn) for task_arn in task_arns[:10]]


def task_definition_from_snapshot(snapshot: dict[str, Any]) -> str | None:
    service_data = snapshot.get("ecs_service", {}).get("data") if isinstance(snapshot.get("ecs_service"), dict) else None
    if isinstance(service_data, list) and service_data:
        task_definition = service_data[0].get("taskDefinition")
        if task_definition:
            return str(task_definition)

    for key in ("ecs_task", "ecs_stopped_task_details"):
        task_data = snapshot.get(key, {}).get("data") if isinstance(snapshot.get(key), dict) else None
        if not isinstance(task_data, list):
            continue
        for task in task_data:
            task_definition = task.get("taskDefinitionArn")
            if task_definition:
                return str(task_definition)
    return None


def collect_ecs_task_definition(task_definition: str, profile: str | None, region: str | None) -> dict[str, Any]:
    return aws_json(
        [
            "ecs",
            "describe-task-definition",
            "--task-definition",
            task_definition,
            "--query",
            "taskDefinition.{taskDefinitionArn:taskDefinitionArn,networkMode:networkMode,requiresCompatibilities:requiresCompatibilities,cpu:cpu,memory:memory,executionRoleArn:executionRoleArn,taskRoleArn:taskRoleArn,containerDefinitions:containerDefinitions[].{name:name,image:image,cpu:cpu,memory:memory,portMappings:portMappings,essential:essential,healthCheck:healthCheck,logConfiguration:logConfiguration.options}}",
        ],
        profile,
        region,
    )


def summarize(snapshot: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []

    def inspect(scope: str, value: Any) -> None:
        if isinstance(value, dict) and value.get("ok") is False:
            blockers.append({"scope": scope, "reason": value.get("error", "command failed")})
        elif isinstance(value, dict):
            for key, child in value.items():
                inspect(f"{scope}.{key}", child)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                inspect(f"{scope}[{index}]", child)

    inspect("raw", snapshot)

    services = snapshot.get("ecs_service", {}).get("data") if isinstance(snapshot.get("ecs_service"), dict) else None
    if isinstance(services, list):
        for svc in services:
            if svc.get("desiredCount") != svc.get("runningCount") or svc.get("pendingCount"):
                findings.append({"severity": "high", "rule": "ecs_desired_running_mismatch", "resource": svc.get("serviceName")})
            for deployment in svc.get("deployments", []) or []:
                rollout = deployment.get("rolloutState")
                if rollout and rollout not in {"COMPLETED", "IN_PROGRESS"}:
                    findings.append({"severity": "high", "rule": "ecs_deployment_not_healthy", "resource": svc.get("serviceName"), "detail": rollout})

    tasks = snapshot.get("ecs_task", {}).get("data") if isinstance(snapshot.get("ecs_task"), dict) else None
    if isinstance(tasks, list):
        for task in tasks:
            reason = task.get("stoppedReason") or task.get("stopCode")
            if reason:
                findings.append({"severity": "high", "rule": "ecs_task_stopped", "resource": task.get("taskArn"), "detail": reason})

    alarms = snapshot.get("alarms", {}).get("data") if isinstance(snapshot.get("alarms"), dict) else None
    if isinstance(alarms, list):
        for alarm in alarms[:10]:
            findings.append({"severity": "medium", "rule": "cloudwatch_alarm", "resource": alarm.get("AlarmName")})

    return (
        {
            "region": snapshot.get("region"),
            "ecs_service_checked": bool(snapshot.get("ecs_service")),
            "task_definition_checked": bool(snapshot.get("ecs_task_definition")),
            "target_health_checked": bool(snapshot.get("target_health")),
            "log_tail_checked": bool(snapshot.get("log_tail")),
            "ecr_images_checked": len(snapshot.get("ecr_images") or []),
            "cloudtrail_events_checked": bool(snapshot.get("cloudtrail_events")),
            "rds_db_instance_checked": bool(snapshot.get("rds_db_instance")),
            "elasticache_cache_cluster_checked": bool(snapshot.get("elasticache_cache_cluster")),
            "elasticache_replication_group_checked": bool(snapshot.get("elasticache_replication_group")),
            "cloudfront_distribution_checked": bool(snapshot.get("cloudfront_distribution")),
            "route53_hosted_zone_checked": bool(snapshot.get("route53_hosted_zone")),
            "route53_health_check_status_checked": bool(snapshot.get("route53_health_check_status")),
            "finding_count": len(findings),
        },
        findings,
        blockers,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect read-only AWS deployment evidence.")
    parser.add_argument("--profile", help="AWS profile.")
    parser.add_argument("--region", required=True, help="AWS region.")
    parser.add_argument("--cluster", help="ECS cluster name or ARN.")
    parser.add_argument("--service", help="ECS service name.")
    parser.add_argument("--task-arn", help="Specific ECS task ARN.")
    parser.add_argument("--target-group-arn", help="ALB/NLB target group ARN.")
    parser.add_argument("--log-group", help="CloudWatch log group to tail.")
    parser.add_argument("--since", default="2h", help="CloudWatch logs tail window, for example 2h.")
    parser.add_argument("--output", help="Write JSON snapshot to this path.")
    parser.add_argument("--max-workers", type=positive_int, default=8, help=f"Max concurrent AWS CLI checks. {THROTTLING_NOTE}")
    parser.add_argument("--db-instance", help="RDS DB instance identifier.")
    parser.add_argument("--cache-cluster", help="ElastiCache cache cluster identifier.")
    parser.add_argument("--replication-group", help="ElastiCache replication group identifier.")
    parser.add_argument("--distribution-id", help="CloudFront distribution ID.")
    parser.add_argument("--hosted-zone-id", help="Route53 hosted zone ID.")
    parser.add_argument("--health-check-id", help="Route53 health check ID.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not shutil.which("aws"):
        print("aws CLI not found in PATH.", file=sys.stderr)
        return 2

    snapshot: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": args.profile,
        "region": args.region,
        "identity": None,
        "ecs_service": None,
        "ecs_stopped_tasks": None,
        "ecs_task": None,
        "ecs_stopped_task_details": None,
        "ecs_task_definition": None,
        "target_health": None,
        "log_tail": None,
        "alarms": None,
        "cloudtrail_events": None,
        "rds_db_instance": None,
        "elasticache_cache_cluster": None,
        "elasticache_replication_group": None,
        "cloudfront_distribution": None,
        "route53_hosted_zone": None,
        "route53_health_check_status": None,
        "collection": {"max_workers": args.max_workers, "throttling_note": THROTTLING_NOTE},
    }

    tier1: dict[str, Callable[[], Any]] = {
        "identity": lambda: aws_json(["sts", "get-caller-identity"], args.profile, None),
        "alarms": lambda: aws_json(
            [
                "cloudwatch",
                "describe-alarms",
                "--state-value",
                "ALARM",
                "--query",
                "MetricAlarms[].{AlarmName:AlarmName,Namespace:Namespace,MetricName:MetricName,StateReason:StateReason,UpdatedTimestamp:StateUpdatedTimestamp}",
            ],
            args.profile,
            args.region,
        ),
        "cloudtrail_events": lambda: aws_json(
            [
                "cloudtrail",
                "lookup-events",
                "--start-time",
                since_to_start(args.since),
                "--max-results",
                "50",
                "--query",
                "Events[?EventSource=='ecs.amazonaws.com' || EventSource=='ecr.amazonaws.com' || EventSource=='elasticloadbalancing.amazonaws.com'].{EventTime:EventTime,EventName:EventName,Username:Username,EventSource:EventSource,ResourceName:Resources[0].ResourceName}",
            ],
            args.profile,
            args.region,
            timeout=60,
        ),
    }

    if args.cluster and args.service:
        tier1["ecs_service"] = lambda: aws_json(
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
        tier1["ecs_stopped_tasks"] = lambda: aws_json(
            [
                "ecs",
                "list-tasks",
                "--cluster",
                args.cluster,
                "--service-name",
                args.service,
                "--desired-status",
                "STOPPED",
                "--max-results",
                "10",
            ],
            args.profile,
            args.region,
        )

    if args.target_group_arn:
        tier1["target_health"] = lambda: aws_json(
            ["elbv2", "describe-target-health", "--target-group-arn", args.target_group_arn],
            args.profile,
            args.region,
        )

    if args.log_group:
        tier1["log_tail"] = lambda: run(
            scoped(["logs", "tail", args.log_group, "--since", args.since, "--format", "short"], args.profile, args.region),
            timeout=90,
            parse_json=False,
        )

    if args.db_instance:
        tier1["rds_db_instance"] = lambda: collect_rds_db_instance(args.db_instance, args.profile, args.region)
    if args.cache_cluster:
        tier1["elasticache_cache_cluster"] = lambda: collect_elasticache_cache_cluster(args.cache_cluster, args.profile, args.region)
    if args.replication_group:
        tier1["elasticache_replication_group"] = lambda: collect_elasticache_replication_group(args.replication_group, args.profile, args.region)
    if args.distribution_id:
        tier1["cloudfront_distribution"] = lambda: collect_cloudfront_distribution(args.distribution_id, args.profile)
    if args.hosted_zone_id:
        tier1["route53_hosted_zone"] = lambda: collect_route53_hosted_zone(args.hosted_zone_id, args.profile)
    if args.health_check_id:
        tier1["route53_health_check_status"] = lambda: collect_route53_health_check_status(args.health_check_id, args.profile)

    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        snapshot.update(run_tier(executor, tier1))

        task_query = (
            "tasks[].{taskArn:taskArn,lastStatus:lastStatus,desiredStatus:desiredStatus,stopCode:stopCode,"
            "stoppedReason:stoppedReason,containers:containers[].{name:name,lastStatus:lastStatus,exitCode:exitCode,"
            "reason:reason,healthStatus:healthStatus,image:image},taskDefinitionArn:taskDefinitionArn,createdAt:createdAt,"
            "startedAt:startedAt,stoppedAt:stoppedAt}"
        )
        tier2: dict[str, Callable[[], Any]] = {}
        task_arns = stopped_task_arns(snapshot.get("ecs_stopped_tasks"))
        if args.cluster and task_arns:
            stopped_task_key = "ecs_stopped_task_details" if args.task_arn else "ecs_task"
            tier2[stopped_task_key] = lambda task_arns=task_arns: aws_json(
                [
                    "ecs",
                    "describe-tasks",
                    "--cluster",
                    args.cluster,
                    "--tasks",
                    *task_arns,
                    "--query",
                    task_query,
                ],
                args.profile,
                args.region,
            )

        if args.cluster and args.task_arn:
            tier2["ecs_task"] = lambda: aws_json(
                [
                    "ecs",
                    "describe-tasks",
                    "--cluster",
                    args.cluster,
                    "--tasks",
                    args.task_arn,
                    "--query",
                    task_query,
                ],
                args.profile,
                args.region,
            )

        task_definition = task_definition_from_snapshot(snapshot)
        if task_definition:
            tier2["ecs_task_definition"] = lambda task_definition=task_definition: collect_ecs_task_definition(task_definition, args.profile, args.region)

        snapshot.update(run_tier(executor, tier2))

        if not snapshot.get("ecs_task_definition"):
            task_definition = task_definition_from_snapshot(snapshot)
            if task_definition:
                snapshot.update(
                    run_tier(
                        executor,
                        {"ecs_task_definition": lambda task_definition=task_definition: collect_ecs_task_definition(task_definition, args.profile, args.region)},
                    )
                )
        if snapshot.get("ecs_task_definition"):
            snapshot["ecr_images"] = collect_ecr_images(snapshot["ecs_task_definition"], args.profile, args.region)

    summary, findings, blockers = summarize(snapshot)
    result = {
        "summary": summary,
        "findings": findings,
        "evidence": {
            "identity": snapshot.get("identity"),
            "deployment_correlation": {
                "cluster": args.cluster,
                "service": args.service,
                "target_group_arn": args.target_group_arn,
                "log_group": args.log_group,
                "since": args.since,
                "db_instance": args.db_instance,
                "cache_cluster": args.cache_cluster,
                "replication_group": args.replication_group,
                "distribution_id": args.distribution_id,
                "hosted_zone_id": args.hosted_zone_id,
                "health_check_id": args.health_check_id,
            },
            "collection": {
                "max_workers": args.max_workers,
                "throttling_note": THROTTLING_NOTE,
            },
        },
        "blockers": blockers,
        "next_commands": [
            "aws ecs describe-services --cluster <cluster> --services <service>",
            "aws logs tail <log-group> --since 2h --format short",
            "aws cloudtrail lookup-events --start-time <timestamp>",
        ],
        "raw": snapshot,
    }

    payload = json.dumps(result, indent=2, sort_keys=True, default=str)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
