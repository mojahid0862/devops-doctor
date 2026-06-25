# DevOps Doctor

DevOps Doctor is a Codex plugin for fast, read-only DevOps/SRE work across GitLab CI/CD, AWS stack health, Terraform, Docker, Kubernetes, web/mobile apps, cost review, security drift, observability, and rollback planning.

It is designed to collect evidence from local authenticated CLIs and repo files, report blockers clearly when tools or permissions are missing, and pair risky production changes with validation and rollback guidance. Normal MR reviews use a fast score-based path; failed pipelines and incidents trigger deeper root-cause evidence.

## Install

Add this repository as a Codex plugin marketplace:

```bash
codex plugin marketplace add https://github.com/mojahid0862/devops-doctor.git --ref main
```

Install the plugin:

```bash
codex plugin add devops-doctor@devops-doctor
```

Start a new Codex thread after installation so the plugin skills are loaded.

## Included Skills

- AWS deployment doctor
- Cost optimizer
- DevOps doctor
- DevOps operator
- ECS/Fargate doctor
- GitLab MR review
- GitLab pipeline doctor
- Observability doctor
- Rollback planner
- Security drift check
- Terraform plan review

## Included Helpers

- `gitlab_mr_fast_review.py`: fast MR score, changed-file risk buckets, CI status, and merge verdict.
- `gitlab_pipeline_snapshot.py`: failed pipeline/job evidence with root-cause candidates.
- `aws_stack_snapshot.py`: bounded AWS stack summary for ECS, RDS, ElastiCache, S3, CloudFront, Route 53, Lambda, CloudWatch, ECR, and CloudTrail.
- `aws_deploy_snapshot.py`: ECS/Fargate deploy correlation with task, target health, ECR, CloudTrail, alarms, and logs.
- `repo_devops_scan.py`: web/mobile/CI/Docker/IaC repo signals and secret-risk patterns.

## Safety

This plugin does not include secrets or credentials. It expects users to authenticate local tools such as `aws`, `glab`, `kubectl`, or `terraform` themselves.

For production work, review proposed changes before approval and run the smallest relevant validation command before rollout.
