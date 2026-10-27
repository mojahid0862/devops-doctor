---
name: terraform-plan-review
description: Review Terraform plans and IaC diffs for destructive changes, replacements, IAM privilege creep, public exposure, missing encryption, deletion protection, unsafe security groups, cost spikes, tagging gaps, drift, and rollout safety. Use when the user shares Terraform code, a terraform plan, plan JSON, or asks if an infrastructure change is safe.
---

# Terraform Plan Review

Read [the shared evidence contract](../devops-doctor/references/evidence-contract.md). Resolve `<plugin-root>` from this skill's absolute path; preserve the user repository cwd.


## Rules

- Never run `terraform apply` unless the user explicitly approves that exact action.
- Treat production infrastructure as sensitive.
- Prefer `terraform plan -out=<protected-temp-dir>/tfplan` plus `terraform show -json <protected-temp-dir>/tfplan` for exact evidence.
- Flag destructive, irreversible, public, or cost-increasing changes before fixes.
- Do not claim plan impact unless it comes from Terraform output, IaC files, user-provided plan text/JSON. A blocker means evidence is unavailable, not a verified system state.
- If evidence is missing, write `Unknown:` or `Blocked:` instead of guessing.

## Workflow

1. Inspect current workspace and backend/provider context:

```bash
terraform workspace show
terraform providers
terraform validate
terraform plan -out=<protected-temp-dir>/tfplan
terraform show -json <protected-temp-dir>/tfplan > <protected-temp-dir>/tfplan.json
```

2. Run the helper:

```bash
python "<plugin-root>/scripts/terraform_plan_guard.py" --plan-json <protected-temp-dir>/tfplan.json --output terraform-plan-risk.json
```

3. Review for:

- deletes, replacements, taints, recreate-before-destroy gaps
- IAM `*` action/resource, broad principals, policy drift
- public security group ingress and `0.0.0.0/0`
- public S3, missing encryption/versioning/lifecycle
- RDS deletion protection, backups, storage, public access
- ALB/NLB exposure, TLS, logging, health checks
- cost-risk resources: NAT, large RDS/EC2, EBS, logs, EIPs

## Output

```text
Critical:
Destructive:
Security:
Cost:
Reliability:
Validate:
Rollback:
Risk:
```

Keep raw plans outside tracked files with restricted access. Delete temporary plan artifacts after review; keep only sanitized findings. Unknown plan values require follow-up; they are not a safe result.
