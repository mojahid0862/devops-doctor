#!/usr/bin/env python3
"""Collect bounded read-only AWS deployment evidence."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
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

    payload = json.dumps(snapshot, indent=2, sort_keys=True, default=str)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
