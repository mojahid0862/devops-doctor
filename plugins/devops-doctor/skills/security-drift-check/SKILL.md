---
name: security-drift-check
description: Check cloud, GitLab CI/CD, Docker, Kubernetes, Terraform, IAM, S3, security groups, secrets handling, public exposure, dependency supply chain, and observability security drift without exposing secret values. Use when the user asks for DevOps security review, drift check, hardening, OWASP/cloud risk, or safe production posture.
---

# Security Drift Check

## Rules

- Do not print secret values. Report file, line, and risk category only.
- Use read-only cloud and repo evidence first.
- Do not change IAM, security groups, bucket policies, CI variables, or keys without explicit approval.
- Prioritize exploitable public exposure and secret leakage over style issues.
- Do not claim exposure, IAM risk, or drift unless it comes from repo scan, cloud CLI output, user-provided evidence, or an explicit blocker.
- If evidence is missing, write `Unknown:` or `Blocked:` instead of guessing.

## Workflow

1. Scan repo-local CI, Docker, Terraform, Compose, and Helm/Kubernetes files:

```bash
python ../../scripts/repo_devops_scan.py --root . --output devops-security-scan.json
```

2. For AWS, capture only needed read-only evidence:

```bash
python ../../scripts/aws_stack_snapshot.py --region <region> --services ecs,rds,elasticache,s3,cloudfront,route53,lambda,cloudwatch,ecr,cloudtrail --output aws-security-snapshot.json
```

3. Prefer helper `findings`, `evidence`, and `blockers`, then check:

- public SG ingress, public S3, missing encryption/versioning/logging, CloudFront TLS/origin exposure, Route 53 risky records
- IAM wildcard actions/resources and broad trust policies
- Docker root user, `latest` tags, privileged containers
- GitLab CI masked/protected variable handling and unsafe deploy rules
- Terraform public exposure, deletion protection, logging gaps
- webhook secrets, API tokens, hardcoded credentials, private keys, mobile permissions, and public frontend env-name exposure

## Output

```text
Critical:
High:
Medium:
Evidence:
Fix:
Validate:
Risk:
```
