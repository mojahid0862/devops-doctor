---
name: ecs-fargate-doctor
description: Diagnose ECS and Fargate service failures, stopped tasks, unhealthy ALB targets, image pull errors, task definition drift, capacity provider issues, CPU/memory pressure, CloudWatch logs, IAM execution role problems, and deployment rollbacks. Use when the user mentions ECS, Fargate, task stopped, target health, container exit, or service not stable.
---

# ECS Fargate Doctor

Read [the shared evidence contract](../devops-doctor/references/evidence-contract.md). Resolve `<plugin-root>` from this skill's absolute path; preserve the user repository cwd.


## Rules

- Read-only first. Do not update services, force deploys, scale, deregister targets, or roll back without explicit approval.
- Avoid dumping task environment variables or secret values.
- Prefer cluster/service/task evidence over guesses.
- Claim current ECS state only from current runtime evidence with source and time, including the connected AWS read tool or CLI. Repo/IaC establishes intent; older logs or screenshots need freshness checks. A blocker means evidence is unavailable, not healthy.
- If evidence is missing, write `Unknown:` or `Blocked:` instead of guessing.

## Workflow

1. Identify cluster, service, region, task ARN, target group, log group, image tag, and last successful deployment.
2. Reuse fresh, complete evidence for the same resource/window. Collect only missing or stale signals through the connected AWS read tool when available; do not repeat a complete snapshot. If CLI is the configured transport, the helper is:

```bash
python "<plugin-root>/scripts/aws_deploy_snapshot.py" --region <region> --cluster <cluster> --service <service> --target-group-arn <tg-arn> --log-group <log-group> --since 2h --output ecs-snapshot.json
```

3. Prefer the helper output's `summary`, `findings`, `evidence.deployment_correlation`, and `blockers`, then check:

- service desired/running/pending counts and deployment rollout state
- last 10 service events
- stopped task reasons and container exit codes
- image pull/auth errors, ECR digest/tag availability, and mutable tag drift
- target group health and health-check path/port
- execution role, task role, logging config, CPU/memory, ulimits
- security group, subnet route, NAT, ALB listener, and container port mapping

## Output

```text
Root cause:
Failed component:
Evidence:
Fix:
Validate:
Rollback:
Risk:
```
