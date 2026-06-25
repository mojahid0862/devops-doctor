---
name: ecs-fargate-doctor
description: Diagnose ECS and Fargate service failures, stopped tasks, unhealthy ALB targets, image pull errors, task definition drift, capacity provider issues, CPU/memory pressure, CloudWatch logs, IAM execution role problems, and deployment rollbacks. Use when the user mentions ECS, Fargate, task stopped, target health, container exit, or service not stable.
---

# ECS Fargate Doctor

## Rules

- Read-only first. Do not update services, force deploys, scale, deregister targets, or roll back without explicit approval.
- Avoid dumping task environment variables or secret values.
- Prefer cluster/service/task evidence over guesses.
- Do not claim ECS current state unless it comes from AWS CLI output, repo/IaC config, user-provided logs, or an explicit blocker.
- If evidence is missing, write `Unknown:` or `Blocked:` instead of guessing.

## Workflow

1. Identify cluster, service, region, task ARN, target group, log group, image tag, and last successful deployment.
2. Capture service evidence:

```bash
python ../../scripts/aws_deploy_snapshot.py --region <region> --cluster <cluster> --service <service> --target-group-arn <tg-arn> --log-group <log-group> --output ecs-snapshot.json
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
