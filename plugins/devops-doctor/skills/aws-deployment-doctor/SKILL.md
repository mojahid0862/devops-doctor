---
name: aws-deployment-doctor
description: Diagnose AWS deployment failures and production incidents with read-only evidence first across ECS/Fargate, EC2, Lambda, ALB/NLB, RDS, ElastiCache/Redis, S3, CloudFront, Route 53, IAM, VPC/security groups, CloudWatch, CloudTrail, GitLab deploy jobs, and rollback paths. Use when the user reports an AWS deploy failure, outage, unhealthy target, failed release, or cloud incident.
---

# AWS Deployment Doctor

## Rules

- Use read-only AWS CLI commands first.
- Do not scale, deploy, delete, rotate, apply Terraform, modify security groups, or run rollback commands without explicit approval.
- Confirm account/region/profile before interpreting evidence.
- Do not print secrets, full env vars, access keys, private data, or sensitive tags.
- Flag unsafe or breaking actions before giving commands.
- Do not claim AWS current state unless it comes from AWS CLI output, repo/IaC config, user-provided logs, or an explicit blocker.
- If evidence is missing, write `Unknown:` or `Blocked:` instead of guessing.

## Workflow

1. Identify service, region, account, recent change, expected health check, and user impact.
2. Verify scope:

```bash
aws sts get-caller-identity
aws configure list
```

3. Use bounded snapshots:

```bash
python ../../scripts/aws_deploy_snapshot.py --region <region> --cluster <cluster> --service <service> --target-group-arn <tg-arn> --log-group <log-group> --since 2h --output aws-deploy-snapshot.json
python ../../scripts/aws_infra_snapshot.py --region <region> --services ec2,ecs,rds,lambda,elbv2,cloudwatch,s3,cloudfront,route53,elasticache --output aws-infra-snapshot.json
python ../../scripts/aws_stack_snapshot.py --region <region> --services ecs,rds,elasticache,s3,cloudfront,route53,lambda,cloudwatch,ecr,cloudtrail --output aws-stack-snapshot.json
```

Add `--db-instance <db>`, `--cache-cluster <cluster>`, `--replication-group <group>`, `--distribution-id <id>`, `--hosted-zone-id <zone>`, or `--health-check-id <id>` to `aws_deploy_snapshot.py` when the incident may cross database, cache, CDN, or DNS layers.

4. Correlate deploy timeline with service events, target health, failed tasks, logs, ECR image digests/tags, CloudTrail events, metrics, alarms, GitLab deploy job output, and recent IaC changes.
5. Separate root cause from symptoms: IAM, image pull, container exit, health check, networking, capacity, config, database, DNS/CDN, dependency, or app code.
6. For CDN/DNS failures, check CloudFront status/origins/certs, cache behavior, invalidation timing, Route 53 record targets, TTLs, health checks, and recent CloudTrail changes.
7. For ElastiCache/Redis health, check cluster status, failover events, CPU/memory, evictions, current connections, replication lag, subnet/SG reachability, and app timeout settings.

## Output

```text
Root cause:
Evidence:
Fix:
Validate:
Rollback:
Risk:
```
