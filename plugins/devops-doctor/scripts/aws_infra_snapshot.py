#!/usr/bin/env python3
"""Read-only AWS CLI snapshot helper for DevOps Doctor."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


DEFAULT_MAX_WORKERS = 8
DEFAULT_SERVICES = [
    "ec2",
    "ecs",
    "rds",
    "lambda",
    "elbv2",
    "cloudwatch",
    "s3",
    "cloudfront",
    "route53",
    "elasticache",
]
RDS_METRICS = {
    "CPUUtilization": "Average",
    "DatabaseConnections": "Average",
    "FreeableMemory": "Average",
    "ReadLatency": "Average",
    "WriteLatency": "Average",
}
LAMBDA_METRICS = {
    "Invocations": "Sum",
    "Errors": "Sum",
    "Throttles": "Sum",
    "Duration": "Average",
}
S3_MISSING_CONFIG_ERRORS = (
    "NoSuchBucketPolicy",
    "NoSuchPublicAccessBlockConfiguration",
    "ServerSideEncryptionConfigurationNotFoundError",
)


def run_aws(args: list[str], timeout: int = 45) -> dict[str, Any]:
    command = ["aws", *args, "--output", "json"]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "command": safe_command(command)}

    if completed.returncode != 0:
        return {
            "ok": False,
            "error": completed.stderr.strip()[-1200:],
            "command": safe_command(command),
        }

    stdout = completed.stdout.strip()
    if not stdout:
        return {"ok": True, "data": None, "command": safe_command(command)}

    try:
        return {"ok": True, "data": json.loads(stdout), "command": safe_command(command)}
    except json.JSONDecodeError:
        return {"ok": True, "data": stdout[-2000:], "command": safe_command(command)}


def safe_command(command: list[str]) -> str:
    return " ".join(command)


def with_scope(base: list[str], profile: str | None, region: str | None) -> list[str]:
    scoped = list(base)
    if profile:
        scoped.extend(["--profile", profile])
    if region:
        scoped.extend(["--region", region])
    return scoped


def bounded_items(items: list[Any], limit: int) -> tuple[list[Any], dict[str, Any]]:
    shown = min(len(items), limit)
    return items[:shown], {
        "total": len(items),
        "shown": shown,
        "truncated": len(items) > shown,
    }


def failed_job(error: Exception) -> dict[str, Any]:
    return {"ok": False, "error": f"{type(error).__name__}: {error}"}


def run_parallel_jobs(jobs: list[tuple[str, Callable[[], Any]]], max_workers: int) -> dict[str, Any]:
    if not jobs:
        return {}

    results: dict[str, Any] = {}
    worker_count = max(1, min(max_workers, len(jobs)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {executor.submit(job): name for name, job in jobs}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as error:
                results[name] = failed_job(error)
    return results


def run_aws_jobs(
    jobs: dict[str, list[str]],
    profile: str | None,
    region: str | None,
    max_workers: int,
    timeout: int = 45,
) -> dict[str, Any]:
    return run_parallel_jobs(
        [
            (name, lambda command=command: run_aws(with_scope(command, profile, region), timeout=timeout))
            for name, command in jobs.items()
        ],
        max_workers,
    )


def metric_window() -> tuple[str, str]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=60)
    return (
        start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def collect_metric(
    profile: str | None,
    region: str,
    namespace: str,
    metric_name: str,
    dimension_name: str,
    dimension_value: str,
    statistic: str,
    start_time: str,
    end_time: str,
) -> dict[str, Any]:
    return run_aws(
        with_scope(
            [
                "cloudwatch",
                "get-metric-statistics",
                "--namespace",
                namespace,
                "--metric-name",
                metric_name,
                "--dimensions",
                f"Name={dimension_name},Value={dimension_value}",
                "--start-time",
                start_time,
                "--end-time",
                end_time,
                "--period",
                "300",
                "--statistics",
                statistic,
            ],
            profile,
            region,
        )
    )


def collect_identity(profile: str | None) -> dict[str, Any]:
    return run_aws(with_scope(["sts", "get-caller-identity"], profile, None))


def collect_ec2(
    profile: str | None,
    region: str,
    max_workers: int = DEFAULT_MAX_WORKERS,
    include_metrics: bool = True,
) -> dict[str, Any]:
    return run_aws_jobs(
        {
            "instances": [
                "ec2",
                "describe-instances",
                "--query",
                "Reservations[].Instances[].{InstanceId:InstanceId,State:State.Name,Type:InstanceType,AZ:Placement.AvailabilityZone,LaunchTime:LaunchTime,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress,SubnetId:SubnetId,VpcId:VpcId,SecurityGroups:SecurityGroups[].GroupId,Tags:Tags}",
            ],
            "volumes": [
                "ec2",
                "describe-volumes",
                "--query",
                "Volumes[].{VolumeId:VolumeId,State:State,Size:Size,Type:VolumeType,Iops:Iops,Throughput:Throughput,Encrypted:Encrypted,Attachments:Attachments[].InstanceId,CreateTime:CreateTime,Tags:Tags}",
            ],
            "addresses": [
                "ec2",
                "describe-addresses",
                "--query",
                "Addresses[].{AllocationId:AllocationId,PublicIp:PublicIp,AssociationId:AssociationId,InstanceId:InstanceId,NetworkInterfaceId:NetworkInterfaceId,Tags:Tags}",
            ],
            "security_groups": [
                "ec2",
                "describe-security-groups",
                "--query",
                "SecurityGroups[].{GroupId:GroupId,GroupName:GroupName,VpcId:VpcId,IpPermissions:IpPermissions,IpPermissionsEgress:IpPermissionsEgress,Tags:Tags}",
            ],
        },
        profile,
        region,
        max_workers,
    )


def describe_ecs_services(profile: str | None, region: str, cluster: str, services: list[str]) -> dict[str, Any]:
    result = run_aws(
        with_scope(
            [
                "ecs",
                "describe-services",
                "--cluster",
                cluster,
                "--services",
                *services,
                "--query",
                "services[].{serviceName:serviceName,status:status,desiredCount:desiredCount,runningCount:runningCount,pendingCount:pendingCount,launchType:launchType,taskDefinition:taskDefinition,deployments:deployments,events:events,loadBalancers:loadBalancers,capacityProviderStrategy:capacityProviderStrategy}",
            ],
            profile,
            region,
        )
    )
    described_services = result.get("data", [])
    if isinstance(described_services, list):
        for service in described_services:
            if not isinstance(service, dict):
                continue
            events = service.get("events", [])
            if isinstance(events, list):
                bounded_events, event_bounds = bounded_items(events, 10)
                service["events"] = bounded_events
                service["event_bounds"] = event_bounds
    return result


def collect_ecs(
    profile: str | None,
    region: str,
    max_workers: int = DEFAULT_MAX_WORKERS,
    include_metrics: bool = True,
) -> dict[str, Any]:
    clusters_result = run_aws(with_scope(["ecs", "list-clusters"], profile, region))
    clusters = clusters_result.get("data", {}).get("clusterArns", []) if clusters_result.get("ok") else []
    bounded_clusters, cluster_bounds = bounded_items(clusters, 25)
    services: list[dict[str, Any]] = []

    for cluster in bounded_clusters:
        listed = run_aws(with_scope(["ecs", "list-services", "--cluster", cluster], profile, region))
        service_arns = listed.get("data", {}).get("serviceArns", []) if listed.get("ok") else []
        bounded_services, service_bounds = bounded_items(service_arns, 100)
        service_jobs: list[tuple[str, Callable[[], Any]]] = []

        for index in range(0, len(bounded_services), 10):
            chunk = bounded_services[index : index + 10]
            if not chunk:
                continue
            service_jobs.append(
                (
                    str(index // 10),
                    lambda cluster=cluster, chunk=chunk: describe_ecs_services(profile, region, cluster, chunk),
                )
            )
        service_results = run_parallel_jobs(service_jobs, max_workers)
        for key in sorted(service_results, key=int):
            services.append(
                {
                    "cluster": cluster,
                    "service_bounds": service_bounds,
                    "services": service_results[key],
                }
            )

    return {"clusters": clusters_result, "cluster_bounds": cluster_bounds, "services": services}


def collect_rds_metrics(
    profile: str | None,
    region: str,
    instances: Any,
    max_workers: int,
) -> dict[str, Any]:
    db_instances = instances if isinstance(instances, list) else []
    bounded_instances, bounds = bounded_items(db_instances, 5)
    start_time, end_time = metric_window()
    jobs: list[tuple[str, Callable[[], Any]]] = []

    for db in bounded_instances:
        db_id = db.get("DBInstanceIdentifier") if isinstance(db, dict) else None
        if not db_id:
            continue
        for metric_name, statistic in RDS_METRICS.items():
            jobs.append(
                (
                    f"{db_id}|{metric_name}",
                    lambda db_id=db_id, metric_name=metric_name, statistic=statistic: collect_metric(
                        profile,
                        region,
                        "AWS/RDS",
                        metric_name,
                        "DBInstanceIdentifier",
                        db_id,
                        statistic,
                        start_time,
                        end_time,
                    ),
                )
            )

    metric_results = run_parallel_jobs(jobs, max_workers)
    items = []
    for db in bounded_instances:
        db_id = db.get("DBInstanceIdentifier") if isinstance(db, dict) else None
        if not db_id:
            continue
        items.append(
            {
                "DBInstanceIdentifier": db_id,
                "metrics": {
                    metric_name: metric_results.get(f"{db_id}|{metric_name}")
                    for metric_name in RDS_METRICS
                },
            }
        )

    return {
        "window_minutes": 60,
        "period_seconds": 300,
        "start_time": start_time,
        "end_time": end_time,
        "instances": {**bounds, "items": items},
    }


def collect_rds(
    profile: str | None,
    region: str,
    max_workers: int = DEFAULT_MAX_WORKERS,
    include_metrics: bool = True,
) -> dict[str, Any]:
    result = run_aws_jobs(
        {
            "instances": [
                "rds",
                "describe-db-instances",
                "--query",
                "DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,DBInstanceClass:DBInstanceClass,Engine:Engine,EngineVersion:EngineVersion,DBInstanceStatus:DBInstanceStatus,AllocatedStorage:AllocatedStorage,StorageType:StorageType,MultiAZ:MultiAZ,PubliclyAccessible:PubliclyAccessible,StorageEncrypted:StorageEncrypted,BackupRetentionPeriod:BackupRetentionPeriod,DeletionProtection:DeletionProtection,VpcSecurityGroups:VpcSecurityGroups[].VpcSecurityGroupId}",
            ],
            "clusters": [
                "rds",
                "describe-db-clusters",
                "--query",
                "DBClusters[].{DBClusterIdentifier:DBClusterIdentifier,Engine:Engine,EngineVersion:EngineVersion,Status:Status,MultiAZ:MultiAZ,StorageEncrypted:StorageEncrypted,BackupRetentionPeriod:BackupRetentionPeriod,DeletionProtection:DeletionProtection,DBClusterMembers:DBClusterMembers[].DBInstanceIdentifier}",
            ],
        },
        profile,
        region,
        max_workers,
    )
    if include_metrics:
        result["metrics"] = collect_rds_metrics(
            profile,
            region,
            result.get("instances", {}).get("data", []),
            max_workers,
        )
    return result


def collect_lambda_metrics(
    profile: str | None,
    region: str,
    functions: Any,
    max_workers: int,
) -> dict[str, Any]:
    lambda_functions = functions if isinstance(functions, list) else []
    bounded_functions, bounds = bounded_items(lambda_functions, 10)
    start_time, end_time = metric_window()
    jobs: list[tuple[str, Callable[[], Any]]] = []

    for function in bounded_functions:
        function_name = function.get("FunctionName") if isinstance(function, dict) else None
        if not function_name:
            continue
        for metric_name, statistic in LAMBDA_METRICS.items():
            jobs.append(
                (
                    f"{function_name}|{metric_name}",
                    lambda function_name=function_name, metric_name=metric_name, statistic=statistic: collect_metric(
                        profile,
                        region,
                        "AWS/Lambda",
                        metric_name,
                        "FunctionName",
                        function_name,
                        statistic,
                        start_time,
                        end_time,
                    ),
                )
            )

    metric_results = run_parallel_jobs(jobs, max_workers)
    items = []
    for function in bounded_functions:
        function_name = function.get("FunctionName") if isinstance(function, dict) else None
        if not function_name:
            continue
        items.append(
            {
                "FunctionName": function_name,
                "metrics": {
                    metric_name: metric_results.get(f"{function_name}|{metric_name}")
                    for metric_name in LAMBDA_METRICS
                },
            }
        )

    return {
        "window_minutes": 60,
        "period_seconds": 300,
        "start_time": start_time,
        "end_time": end_time,
        "functions": {**bounds, "items": items},
    }


def collect_lambda(
    profile: str | None,
    region: str,
    max_workers: int = DEFAULT_MAX_WORKERS,
    include_metrics: bool = True,
) -> dict[str, Any]:
    result = {
        "functions": run_aws(
            with_scope(
                [
                    "lambda",
                    "list-functions",
                    "--query",
                    "Functions[].{FunctionName:FunctionName,Runtime:Runtime,MemorySize:MemorySize,Timeout:Timeout,LastModified:LastModified,PackageType:PackageType,State:State,Architectures:Architectures}",
                ],
                profile,
                region,
            )
        )
    }
    if include_metrics:
        result["metrics"] = collect_lambda_metrics(
            profile,
            region,
            result.get("functions", {}).get("data", []),
            max_workers,
        )
    return result


def collect_elbv2(
    profile: str | None,
    region: str,
    max_workers: int = DEFAULT_MAX_WORKERS,
    include_metrics: bool = True,
) -> dict[str, Any]:
    return run_aws_jobs(
        {
            "load_balancers": [
                "elbv2",
                "describe-load-balancers",
                "--query",
                "LoadBalancers[].{LoadBalancerArn:LoadBalancerArn,LoadBalancerName:LoadBalancerName,Type:Type,Scheme:Scheme,State:State.Code,VpcId:VpcId,DNSName:DNSName,CreatedTime:CreatedTime}",
            ],
            "target_groups": [
                "elbv2",
                "describe-target-groups",
                "--query",
                "TargetGroups[].{TargetGroupArn:TargetGroupArn,TargetGroupName:TargetGroupName,Protocol:Protocol,Port:Port,VpcId:VpcId,TargetType:TargetType,HealthCheckPath:HealthCheckPath}",
            ],
        },
        profile,
        region,
        max_workers,
    )


def collect_cloudwatch(
    profile: str | None,
    region: str,
    max_workers: int = DEFAULT_MAX_WORKERS,
    include_metrics: bool = True,
) -> dict[str, Any]:
    return {
        "alarms": run_aws(
            with_scope(
                [
                    "cloudwatch",
                    "describe-alarms",
                    "--state-value",
                    "ALARM",
                    "--query",
                    "MetricAlarms[].{AlarmName:AlarmName,StateValue:StateValue,StateReason:StateReason,Namespace:Namespace,MetricName:MetricName,Dimensions:Dimensions,UpdatedTimestamp:StateUpdatedTimestamp}",
                ],
                profile,
                region,
            )
        )
    }


def collect_s3(
    profile: str | None,
    region: str,
    max_workers: int = DEFAULT_MAX_WORKERS,
    include_metrics: bool = True,
) -> dict[str, Any]:
    def run_s3_bucket_config(command: list[str]) -> dict[str, Any]:
        result = run_aws(with_scope(command, profile, None))
        error = result.get("error", "")
        if result.get("ok") is False and any(token in error for token in S3_MISSING_CONFIG_ERRORS):
            return {**result, "ok": True, "missing": True}
        return result

    buckets_result = run_aws(
        with_scope(
            [
                "s3api",
                "list-buckets",
                "--query",
                "Buckets[].{Name:Name,CreationDate:CreationDate}",
            ],
            profile,
            None,
        )
    )
    buckets = buckets_result.get("data", []) if buckets_result.get("ok") else []
    buckets = buckets if isinstance(buckets, list) else []
    bounded_buckets, bounds = bounded_items(buckets, 40)
    jobs: list[tuple[str, Callable[[], Any]]] = []

    for bucket in bounded_buckets:
        bucket_name = bucket.get("Name") if isinstance(bucket, dict) else None
        if not bucket_name:
            continue
        bucket_jobs = {
            "location": ["s3api", "get-bucket-location", "--bucket", bucket_name],
            "public_access_block": ["s3api", "get-public-access-block", "--bucket", bucket_name],
            "encryption": ["s3api", "get-bucket-encryption", "--bucket", bucket_name],
            "versioning": ["s3api", "get-bucket-versioning", "--bucket", bucket_name],
            "policy_status": ["s3api", "get-bucket-policy-status", "--bucket", bucket_name],
        }
        for detail_name, command in bucket_jobs.items():
            jobs.append(
                (
                    f"{bucket_name}|{detail_name}",
                    lambda command=command: run_s3_bucket_config(command),
                )
            )

    detail_results = run_parallel_jobs(jobs, max_workers)
    items = []
    for bucket in bounded_buckets:
        bucket_name = bucket.get("Name") if isinstance(bucket, dict) else None
        if not bucket_name:
            continue
        items.append(
            {
                "Name": bucket_name,
                "CreationDate": bucket.get("CreationDate"),
                "location": detail_results.get(f"{bucket_name}|location"),
                "public_access_block": detail_results.get(f"{bucket_name}|public_access_block"),
                "encryption": detail_results.get(f"{bucket_name}|encryption"),
                "versioning": detail_results.get(f"{bucket_name}|versioning"),
                "policy_status": detail_results.get(f"{bucket_name}|policy_status"),
            }
        )

    return {"buckets": buckets_result, "bucket_details": {**bounds, "items": items}}


def collect_cloudfront(
    profile: str | None,
    region: str,
    max_workers: int = DEFAULT_MAX_WORKERS,
    include_metrics: bool = True,
) -> dict[str, Any]:
    return {
        "distributions": run_aws(
            with_scope(
                [
                    "cloudfront",
                    "list-distributions",
                    "--query",
                    "DistributionList.Items[].{Id:Id,DomainName:DomainName,Status:Status,Enabled:Enabled,Aliases:Aliases.Items,Origins:Origins.Items[].{Id:Id,DomainName:DomainName,OriginPath:OriginPath},ViewerProtocolPolicy:DefaultCacheBehavior.ViewerProtocolPolicy}",
                ],
                profile,
                None,
            )
        )
    }


def collect_route53(
    profile: str | None,
    region: str,
    max_workers: int = DEFAULT_MAX_WORKERS,
    include_metrics: bool = True,
) -> dict[str, Any]:
    result = run_aws_jobs(
        {
            "hosted_zones": [
                "route53",
                "list-hosted-zones",
                "--query",
                "HostedZones[].{Id:Id,Name:Name,PrivateZone:Config.PrivateZone,ResourceRecordSetCount:ResourceRecordSetCount}",
            ],
            "health_checks": [
                "route53",
                "list-health-checks",
                "--query",
                "HealthChecks[].{Id:Id,Type:HealthCheckConfig.Type,FullyQualifiedDomainName:HealthCheckConfig.FullyQualifiedDomainName,IPAddress:HealthCheckConfig.IPAddress,Port:HealthCheckConfig.Port,ResourcePath:HealthCheckConfig.ResourcePath}",
            ],
        },
        profile,
        None,
        max_workers,
    )
    health_checks = result.get("health_checks", {}).get("data", [])
    health_checks = health_checks if isinstance(health_checks, list) else []
    bounded_checks, bounds = bounded_items(health_checks, 40)
    status_jobs = []
    for check in bounded_checks:
        check_id = check.get("Id") if isinstance(check, dict) else None
        if not check_id:
            continue
        status_jobs.append(
            (
                check_id,
                lambda check_id=check_id: run_aws(
                    with_scope(
                        ["route53", "get-health-check-status", "--health-check-id", check_id],
                        profile,
                        None,
                    )
                ),
            )
        )
    statuses = run_parallel_jobs(status_jobs, max_workers)
    result["health_check_statuses"] = {
        **bounds,
        "items": [
            {"Id": check_id, "status": statuses.get(check_id)}
            for check_id in sorted(statuses)
        ],
    }
    return result


def collect_elasticache(
    profile: str | None,
    region: str,
    max_workers: int = DEFAULT_MAX_WORKERS,
    include_metrics: bool = True,
) -> dict[str, Any]:
    return run_aws_jobs(
        {
            "cache_clusters": [
                "elasticache",
                "describe-cache-clusters",
                "--show-cache-node-info",
                "--query",
                "CacheClusters[].{CacheClusterId:CacheClusterId,Engine:Engine,EngineVersion:EngineVersion,CacheClusterStatus:CacheClusterStatus,CacheNodeType:CacheNodeType,NumCacheNodes:NumCacheNodes,PreferredAvailabilityZone:PreferredAvailabilityZone,CacheSubnetGroupName:CacheSubnetGroupName,SecurityGroups:SecurityGroups[].SecurityGroupId,CacheNodes:CacheNodes}",
            ],
            "replication_groups": [
                "elasticache",
                "describe-replication-groups",
                "--query",
                "ReplicationGroups[].{ReplicationGroupId:ReplicationGroupId,Status:Status,Engine:Engine,Description:Description,AutomaticFailover:AutomaticFailover,MultiAZ:MultiAZ,ClusterEnabled:ClusterEnabled,TransitEncryptionEnabled:TransitEncryptionEnabled,AtRestEncryptionEnabled:AtRestEncryptionEnabled,MemberClusters:MemberClusters,NodeGroups:NodeGroups}",
            ],
        },
        profile,
        region,
        max_workers,
    )


COLLECTORS = {
    "ec2": collect_ec2,
    "ecs": collect_ecs,
    "rds": collect_rds,
    "lambda": collect_lambda,
    "elbv2": collect_elbv2,
    "cloudwatch": collect_cloudwatch,
    "s3": collect_s3,
    "cloudfront": collect_cloudfront,
    "route53": collect_route53,
    "elasticache": collect_elasticache,
}


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

    rds_instances = snapshot.get("services", {}).get("rds", {}).get("instances", {}).get("data", [])
    for db in rds_instances if isinstance(rds_instances, list) else []:
        if db.get("PubliclyAccessible"):
            findings.append({"severity": "high", "service": "rds", "rule": "publicly_accessible", "resource": db.get("DBInstanceIdentifier")})
        if not db.get("StorageEncrypted"):
            findings.append({"severity": "high", "service": "rds", "rule": "storage_not_encrypted", "resource": db.get("DBInstanceIdentifier")})

    ecs_groups = snapshot.get("services", {}).get("ecs", {}).get("services", [])
    unhealthy = 0
    for group in ecs_groups if isinstance(ecs_groups, list) else []:
        services = group.get("services", {}).get("data", [])
        for service in services if isinstance(services, list) else []:
            if service.get("desiredCount") != service.get("runningCount") or service.get("pendingCount"):
                unhealthy += 1
                findings.append({"severity": "high", "service": "ecs", "rule": "desired_running_mismatch", "resource": service.get("serviceName")})

    alarms = snapshot.get("services", {}).get("cloudwatch", {}).get("alarms", {}).get("data", [])
    if isinstance(alarms, list):
        bounded_alarms, alarm_bounds = bounded_items(alarms, 10)
        for alarm in bounded_alarms:
            findings.append({"severity": "medium", "service": "cloudwatch", "rule": "alarm_in_alarm_state", "resource": alarm.get("AlarmName")})
    else:
        alarm_bounds = {"total": 0, "shown": 0, "truncated": False}

    return (
        {
            "profile": snapshot.get("profile"),
            "region": snapshot.get("region"),
            "services_collected": sorted((snapshot.get("services") or {}).keys()),
            "finding_count": len(findings),
            "blocker_count": len(blockers),
            "ecs_unhealthy_services": unhealthy,
            "cloudwatch_alarm_count": len(alarms) if isinstance(alarms, list) else None,
            "cloudwatch_alarm_findings": alarm_bounds,
        },
        findings,
        blockers,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect a bounded read-only AWS infrastructure snapshot.")
    parser.add_argument("--profile", help="AWS profile name.")
    parser.add_argument("--region", required=True, help="AWS region to inspect, for example us-east-1.")
    parser.add_argument(
        "--services",
        default=",".join(DEFAULT_SERVICES),
        help="Comma-separated services: ec2,ecs,rds,lambda,elbv2,cloudwatch,s3,cloudfront,route53,elasticache.",
    )
    # Bounded concurrency keeps snapshot speed reasonable while reducing AWS API throttling risk.
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Parallel AWS CLI calls; lower if APIs throttle.")
    parser.add_argument("--no-metrics", action="store_true", help="Skip bounded CloudWatch metric enrichment.")
    parser.add_argument("--output", help="Write JSON to this path instead of stdout.")
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

    snapshot: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": args.profile,
        "region": args.region,
        "identity": collect_identity(args.profile),
        "services": {},
    }

    collector_jobs = [
        (
            service,
            lambda service=service: COLLECTORS[service](
                args.profile,
                args.region,
                args.max_workers,
                not args.no_metrics,
            ),
        )
        for service in selected
    ]
    snapshot["services"] = run_parallel_jobs(collector_jobs, args.max_workers)

    summary, findings, blockers = summarize(snapshot)
    result = {
        "summary": summary,
        "findings": findings,
        "evidence": {"identity": snapshot.get("identity")},
        "blockers": blockers,
        "next_commands": [
            "python scripts/aws_stack_snapshot.py --region <region> --services ecs,rds,elasticache,s3,cloudfront,route53,lambda,cloudwatch,ecr,cloudtrail",
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
