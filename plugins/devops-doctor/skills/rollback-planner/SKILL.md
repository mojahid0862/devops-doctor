---
name: rollback-planner
description: Create safe rollback and recovery plans for GitLab deployments, AWS ECS/Fargate, EC2, Lambda, RDS, ElastiCache/Redis, Kubernetes, Terraform, Docker, migrations, feature flags, CloudFront/Route 53 DNS/CDN, and failed releases. Use when the user asks how to roll back, reduce blast radius, recover production, or make a deployment rollback-safe.
---

# Rollback Planner

## Rules

- Do not execute rollback, deploy, database restore, DNS change, Terraform apply, or scaling command without explicit approval.
- State blast radius, data risk, downtime expectation, health checks, and abort condition.
- Prefer reversible steps and preserve forensic evidence.
- Do not claim rollback target, current version, or health state unless it comes from GitLab/AWS/Kubernetes/Terraform output, repo config, user-provided evidence, or an explicit blocker.
- If evidence is missing, write `Unknown:` or `Blocked:` instead of guessing.

## Workflow

1. Identify release artifact, previous good version, deployment mechanism, data changes, and current health.
2. Confirm the rollback target:

- GitLab job/environment/deployment ID
- image tag or task definition revision
- Lambda version/alias
- Helm revision
- Terraform state and previous plan
- DB migration direction and backup state
- For ECS/Fargate, use `aws_deploy_snapshot.py` to capture service revision, task definition, ECR digest/tag, CloudTrail deploy timing, target health, and recent stopped tasks before writing the rollback sequence.
- For DNS/CDN/storage rollback, use `aws_stack_snapshot.py --services s3,cloudfront,route53,cloudtrail`.
- For Redis/ElastiCache rollback, capture cluster status, failover events, replication health, parameter changes, and app endpoint dependencies before endpoint or failover actions.

3. Build the rollback sequence:

- pre-checks and freeze condition
- exact rollback command or manual step
- health checks and monitoring watch
- traffic validation and smoke tests
- stop condition and forward-fix path

## Output

```text
Rollback target:
Pre-checks:
Rollback:
Validate:
Abort if:
Forward fix:
Risk:
```
