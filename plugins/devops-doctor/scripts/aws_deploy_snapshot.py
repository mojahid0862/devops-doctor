#!/usr/bin/env python3
"""Collect bounded read-only AWS deployment evidence."""

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
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
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
        "identity": aws_json(["sts", "get-caller-identity"], args.profile, None),
        "ecs_service": None,
        "ecs_stopped_tasks": None,
        "ecs_task": None,
        "ecs_task_definition": None,
        "target_health": None,
        "log_tail": None,
        "alarms": aws_json(
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
    }

    if args.cluster and args.service:
        snapshot["ecs_service"] = aws_json(
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
        snapshot["ecs_stopped_tasks"] = stopped
        task_arns = []
        if stopped.get("ok"):
            task_arns = stopped.get("data", {}).get("taskArns", [])
        if task_arns:
            snapshot["ecs_task"] = aws_json(
                [
                    "ecs",
                    "describe-tasks",
                    "--cluster",
                    args.cluster,
                    "--tasks",
                    *task_arns[:10],
                    "--query",
                    "tasks[].{taskArn:taskArn,lastStatus:lastStatus,desiredStatus:desiredStatus,stopCode:stopCode,stoppedReason:stoppedReason,containers:containers[].{name:name,lastStatus:lastStatus,exitCode:exitCode,reason:reason,healthStatus:healthStatus,image:image},createdAt:createdAt,startedAt:startedAt,stoppedAt:stoppedAt}",
                ],
                args.profile,
                args.region,
            )

    if args.cluster and args.task_arn:
        snapshot["ecs_task"] = aws_json(
            [
                "ecs",
                "describe-tasks",
                "--cluster",
                args.cluster,
                "--tasks",
                args.task_arn,
                "--query",
                "tasks[].{taskArn:taskArn,lastStatus:lastStatus,desiredStatus:desiredStatus,stopCode:stopCode,stoppedReason:stoppedReason,containers:containers[].{name:name,lastStatus:lastStatus,exitCode:exitCode,reason:reason,healthStatus:healthStatus,image:image},taskDefinitionArn:taskDefinitionArn,createdAt:createdAt,startedAt:startedAt,stoppedAt:stoppedAt}",
            ],
            args.profile,
            args.region,
        )

    task_definition = None
    service_data = snapshot.get("ecs_service", {}).get("data") if isinstance(snapshot.get("ecs_service"), dict) else None
    if service_data:
        task_definition = service_data[0].get("taskDefinition") if service_data else None
    task_data = snapshot.get("ecs_task", {}).get("data") if isinstance(snapshot.get("ecs_task"), dict) else None
    if not task_definition and task_data:
        task_definition = task_data[0].get("taskDefinitionArn") if task_data else None
    if task_definition:
        snapshot["ecs_task_definition"] = aws_json(
            [
                "ecs",
                "describe-task-definition",
                "--task-definition",
                task_definition,
                "--query",
                "taskDefinition.{taskDefinitionArn:taskDefinitionArn,networkMode:networkMode,requiresCompatibilities:requiresCompatibilities,cpu:cpu,memory:memory,executionRoleArn:executionRoleArn,taskRoleArn:taskRoleArn,containerDefinitions:containerDefinitions[].{name:name,image:image,cpu:cpu,memory:memory,portMappings:portMappings,essential:essential,healthCheck:healthCheck,logConfiguration:logConfiguration.options}}",
            ],
            args.profile,
            args.region,
        )
        snapshot["ecr_images"] = collect_ecr_images(snapshot["ecs_task_definition"], args.profile, args.region)

    if args.target_group_arn:
        snapshot["target_health"] = aws_json(
            ["elbv2", "describe-target-health", "--target-group-arn", args.target_group_arn],
            args.profile,
            args.region,
        )

    if args.log_group:
        snapshot["log_tail"] = run(
            scoped(["logs", "tail", args.log_group, "--since", args.since, "--format", "short"], args.profile, args.region),
            timeout=90,
            parse_json=False,
        )

    snapshot["cloudtrail_events"] = aws_json(
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
    )

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
