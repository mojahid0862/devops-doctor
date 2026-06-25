#!/usr/bin/env python3
"""Read-only AWS CLI snapshot helper for DevOps Doctor."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_SERVICES = ["ec2", "ecs", "rds", "lambda", "elbv2", "cloudwatch"]


def run_aws(args: list[str], timeout: int = 45) -> dict[str, Any]:
    command = ["aws", *args, "--output", "json"]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
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


def collect_identity(profile: str | None) -> dict[str, Any]:
    return run_aws(with_scope(["sts", "get-caller-identity"], profile, None))


def collect_ec2(profile: str | None, region: str) -> dict[str, Any]:
    return {
        "instances": run_aws(
            with_scope(
                [
                    "ec2",
                    "describe-instances",
                    "--query",
                    "Reservations[].Instances[].{InstanceId:InstanceId,State:State.Name,Type:InstanceType,AZ:Placement.AvailabilityZone,LaunchTime:LaunchTime,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress,SubnetId:SubnetId,VpcId:VpcId,SecurityGroups:SecurityGroups[].GroupId,Tags:Tags}",
                ],
                profile,
                region,
            )
        ),
        "volumes": run_aws(
            with_scope(
                [
                    "ec2",
                    "describe-volumes",
                    "--query",
                    "Volumes[].{VolumeId:VolumeId,State:State,Size:Size,Type:VolumeType,Iops:Iops,Throughput:Throughput,Encrypted:Encrypted,Attachments:Attachments[].InstanceId,CreateTime:CreateTime,Tags:Tags}",
                ],
                profile,
                region,
            )
        ),
        "addresses": run_aws(
            with_scope(
                [
                    "ec2",
                    "describe-addresses",
                    "--query",
                    "Addresses[].{AllocationId:AllocationId,PublicIp:PublicIp,AssociationId:AssociationId,InstanceId:InstanceId,NetworkInterfaceId:NetworkInterfaceId,Tags:Tags}",
                ],
                profile,
                region,
            )
        ),
        "security_groups": run_aws(
            with_scope(
                [
                    "ec2",
                    "describe-security-groups",
                    "--query",
                    "SecurityGroups[].{GroupId:GroupId,GroupName:GroupName,VpcId:VpcId,IpPermissions:IpPermissions,IpPermissionsEgress:IpPermissionsEgress,Tags:Tags}",
                ],
                profile,
                region,
            )
        ),
    }


def collect_ecs(profile: str | None, region: str) -> dict[str, Any]:
    clusters_result = run_aws(with_scope(["ecs", "list-clusters"], profile, region))
    clusters = clusters_result.get("data", {}).get("clusterArns", []) if clusters_result.get("ok") else []
    services: list[dict[str, Any]] = []

    for cluster in clusters[:25]:
        listed = run_aws(with_scope(["ecs", "list-services", "--cluster", cluster], profile, region))
        service_arns = listed.get("data", {}).get("serviceArns", []) if listed.get("ok") else []
        for index in range(0, len(service_arns[:100]), 10):
            chunk = service_arns[index : index + 10]
            if not chunk:
                continue
            services.append(
                {
                    "cluster": cluster,
                    "services": run_aws(
                        with_scope(
                            [
                                "ecs",
                                "describe-services",
                                "--cluster",
                                cluster,
                                "--services",
                                *chunk,
                                "--query",
                                "services[].{serviceName:serviceName,status:status,desiredCount:desiredCount,runningCount:runningCount,pendingCount:pendingCount,launchType:launchType,taskDefinition:taskDefinition,deployments:deployments,events:events[0:10],loadBalancers:loadBalancers,capacityProviderStrategy:capacityProviderStrategy}",
                            ],
                            profile,
                            region,
                        )
                    ),
                }
            )

    return {"clusters": clusters_result, "services": services}


def collect_rds(profile: str | None, region: str) -> dict[str, Any]:
    return {
        "instances": run_aws(
            with_scope(
                [
                    "rds",
                    "describe-db-instances",
                    "--query",
                    "DBInstances[].{DBInstanceIdentifier:DBInstanceIdentifier,DBInstanceClass:DBInstanceClass,Engine:Engine,EngineVersion:EngineVersion,DBInstanceStatus:DBInstanceStatus,AllocatedStorage:AllocatedStorage,StorageType:StorageType,MultiAZ:MultiAZ,PubliclyAccessible:PubliclyAccessible,StorageEncrypted:StorageEncrypted,BackupRetentionPeriod:BackupRetentionPeriod,DeletionProtection:DeletionProtection,VpcSecurityGroups:VpcSecurityGroups[].VpcSecurityGroupId}",
                ],
                profile,
                region,
            )
        ),
        "clusters": run_aws(
            with_scope(
                [
                    "rds",
                    "describe-db-clusters",
                    "--query",
                    "DBClusters[].{DBClusterIdentifier:DBClusterIdentifier,Engine:Engine,EngineVersion:EngineVersion,Status:Status,MultiAZ:MultiAZ,StorageEncrypted:StorageEncrypted,BackupRetentionPeriod:BackupRetentionPeriod,DeletionProtection:DeletionProtection,DBClusterMembers:DBClusterMembers[].DBInstanceIdentifier}",
                ],
                profile,
                region,
            )
        ),
    }


def collect_lambda(profile: str | None, region: str) -> dict[str, Any]:
    return {
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


def collect_elbv2(profile: str | None, region: str) -> dict[str, Any]:
    lbs = run_aws(
        with_scope(
            [
                "elbv2",
                "describe-load-balancers",
                "--query",
                "LoadBalancers[].{LoadBalancerArn:LoadBalancerArn,LoadBalancerName:LoadBalancerName,Type:Type,Scheme:Scheme,State:State.Code,VpcId:VpcId,DNSName:DNSName,CreatedTime:CreatedTime}",
            ],
            profile,
            region,
        )
    )
    tgs = run_aws(
        with_scope(
            [
                "elbv2",
                "describe-target-groups",
                "--query",
                "TargetGroups[].{TargetGroupArn:TargetGroupArn,TargetGroupName:TargetGroupName,Protocol:Protocol,Port:Port,VpcId:VpcId,TargetType:TargetType,HealthCheckPath:HealthCheckPath}",
            ],
            profile,
            region,
        )
    )
    return {"load_balancers": lbs, "target_groups": tgs}


def collect_cloudwatch(profile: str | None, region: str) -> dict[str, Any]:
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


COLLECTORS = {
    "ec2": collect_ec2,
    "ecs": collect_ecs,
    "rds": collect_rds,
    "lambda": collect_lambda,
    "elbv2": collect_elbv2,
    "cloudwatch": collect_cloudwatch,
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
        for alarm in alarms[:10]:
            findings.append({"severity": "medium", "service": "cloudwatch", "rule": "alarm_in_alarm_state", "resource": alarm.get("AlarmName")})

    return (
        {
            "profile": snapshot.get("profile"),
            "region": snapshot.get("region"),
            "services_collected": sorted((snapshot.get("services") or {}).keys()),
            "finding_count": len(findings),
            "blocker_count": len(blockers),
            "ecs_unhealthy_services": unhealthy,
            "cloudwatch_alarm_count": len(alarms) if isinstance(alarms, list) else None,
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
        help="Comma-separated services: ec2,ecs,rds,lambda,elbv2,cloudwatch.",
    )
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

    for service in selected:
        snapshot["services"][service] = COLLECTORS[service](args.profile, args.region)

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
