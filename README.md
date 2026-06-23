# DevOps Doctor

DevOps Doctor is a Codex plugin for DevOps/SRE work across GitLab CI/CD, AWS, Terraform, Docker, Kubernetes, cost review, security drift, observability, and rollback planning.

It is designed to collect evidence from local authenticated CLIs and repo files, report blockers clearly when tools or permissions are missing, and pair risky production changes with validation and rollback guidance.

## Install

Add this repository as a Codex plugin marketplace:

```bash
codex plugin marketplace add git@github.com:mojahid0862/devops-doctor.git --ref main
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

## Safety

This plugin does not include secrets or credentials. It expects users to authenticate local tools such as `aws`, `glab`, `kubectl`, or `terraform` themselves.

For production work, review proposed changes before approval and run the smallest relevant validation command before rollout.
