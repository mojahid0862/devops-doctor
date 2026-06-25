---
name: cost-optimizer
description: Find AWS cost waste and rightsizing opportunities using read-only Cost Explorer, CloudWatch, EC2, ECS, RDS, EBS, EIP, NAT gateway, load balancer, S3, CloudWatch Logs, and ECR evidence. Use when the user asks to reduce AWS cost, find waste, optimize spend, or check over-provisioning.
---

# Cost Optimizer

## Rules

- Read-only first. Do not resize, delete, purchase savings plans/reservations, change retention, or modify scaling without explicit approval.
- Report savings as estimates unless exact billing data is available.
- Prefer low-risk waste cleanup before architecture changes.
- Do not claim spend, utilization, or savings unless it comes from Cost Explorer, CloudWatch/AWS CLI, repo/IaC config, user-provided evidence, or an explicit blocker.
- If evidence is missing, write `Unknown:` or `Blocked:` instead of guessing.

## Workflow

1. Capture billing trend where Cost Explorer is available:

```bash
python ../../scripts/aws_cost_snapshot.py --days 14 --output aws-cost-snapshot.json
```

2. Capture regional infra when region is known:

```bash
python ../../scripts/aws_stack_snapshot.py --region <region> --services ecs,rds,elasticache,s3,cloudfront,lambda,cloudwatch,ecr --output aws-cost-stack-snapshot.json
```

3. Prefer helper `summary.top_services`, `findings`, and `blockers`, then look for:

- unattached EBS, unused EIP, idle load balancers, old snapshots
- oversized EC2/RDS, low CPU/network, low connections
- ECS CPU/memory reservations much higher than actual usage
- NAT gateway and cross-AZ/data transfer hotspots
- CloudWatch Logs retention too long or unbounded
- stale ECR images and untagged image buildup
- S3 lifecycle gaps and old storage classes
- CloudFront distributions, Route 53 records, and Lambda provisioned concurrency that are no longer attached to active traffic

## Output

```text
Quick wins:
Estimated savings:
Evidence:
Risk:
Validate:
Rollback:
Next:
```
