---
name: cost-optimizer
description: Find AWS cost waste and rightsizing opportunities using read-only Cost Explorer, CloudWatch, EC2, ECS, RDS, ElastiCache/Redis, EBS, EIP, NAT gateway, load balancer, S3, CloudFront, Route 53, CloudWatch Logs, and ECR evidence. Use when the user asks to reduce AWS cost, find waste, optimize spend, or check over-provisioning.
---

# Cost Optimizer

Read [the shared evidence contract](../devops-doctor/references/evidence-contract.md). Resolve `<plugin-root>` from this skill's absolute path; preserve the user repository cwd.


## Rules

- Read-only first. Do not resize, delete, purchase savings plans/reservations, change retention, or modify scaling without explicit approval.
- Report savings as estimates unless exact billing data is available.
- Prefer low-risk waste cleanup before architecture changes.
- Do not claim spend, utilization, or savings unless it comes from Cost Explorer, CloudWatch/AWS CLI, repo/IaC config, user-provided evidence. A blocker means evidence is unavailable, not a verified system state.
- If evidence is missing, write `Unknown:` or `Blocked:` instead of guessing.

## Workflow

1. Capture billing trend where Cost Explorer is available:

```bash
python "<plugin-root>/scripts/aws_cost_snapshot.py" --days 14 --compare-previous --group-by SERVICE,REGION --output aws-cost-snapshot.json
```

2. Fetch only utilization/configuration needed to explain the selected cost groups; knowing a region alone is not a reason for an inventory. If the CLI helper fits, restrict `--services` to those groups, for example:

```bash
python "<plugin-root>/scripts/aws_stack_snapshot.py" --region <region> --services <relevant-services> --output aws-cost-stack-snapshot.json
```

3. Prefer helper `summary.top_groups` (or `summary.top_services` for SERVICE-only grouping), `findings`, and `blockers`, then look for:

- unattached EBS, unused EIP, idle load balancers, old snapshots
- oversized EC2/RDS, low CPU/network, low connections
- ECS CPU/memory reservations much higher than actual usage
- idle or oversized ElastiCache/Redis nodes, replicas, and snapshots
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

## Attribution

Use `--start YYYY-MM-DD --end YYYY-MM-DD` for an exact billing window (end exclusive). Use at most two dimensions from SERVICE, REGION, USAGE_TYPE, OPERATION, LINKED_ACCOUNT. Narrow one AWS service with `--service <exact-service-name>`, then group by USAGE_TYPE,OPERATION to explain a spike. Compare equal-length prior periods with `--compare-previous`. Preserve currency, estimated-cost flags, and scope. A cost increase does not identify an application or imply that the spend is waste.
