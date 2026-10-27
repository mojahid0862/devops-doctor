# DevOps Doctor 0.3.9

DevOps Doctor is a Codex plugin for fast, read-only DevOps/SRE work across GitLab CI/CD, AWS stack health, Terraform, Docker, Kubernetes, web/mobile apps, cost review, security drift, observability, and rollback planning.

It collects evidence from local authenticated CLIs and repo files, reports incomplete evidence and access blockers, and pairs production proposals with validation and rollback guidance. MR reviews require the actual diff and current-commit CI evidence; a heuristic score does not establish merge readiness.

The main agent dispatches ready independent work before detailed investigation or waiting, shares evidence once, and balances assignments within host limits. Assigned workers execute their scope without repeating team planning; independent tests and review can overlap on frozen inputs. This applies across coding, reviews, CI/CD, cost, security, IaC, incidents, and health checks. See the [plugin guide](plugins/devops-doctor/README.md) and [changelog](plugins/devops-doctor/CHANGELOG.md).

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
- DevOps team
- ECS/Fargate doctor
- GitLab MR review
- GitLab pipeline doctor
- Observability doctor
- Rollback planner
- Security drift check
- Terraform plan review

## Included Helpers

- `gitlab_mr_fast_review.py`: current-commit diff/CI evidence, risk indicators, and blockers; incomplete or unverified checks prevent readiness.
- `gitlab_pipeline_snapshot.py`: failed pipeline/job evidence with root-cause candidates.
- `aws_stack_snapshot.py`: bounded AWS stack summary for ECS, RDS, ElastiCache, S3, CloudFront, Route 53, Lambda, CloudWatch, ECR, and CloudTrail.
- `aws_deploy_snapshot.py`: ECS/Fargate deploy correlation with task, target health, ECR, CloudTrail, alarms, and logs.
- `repo_devops_scan.py`: web/mobile/CI/Docker/IaC repo signals and secret-risk patterns.
- `aws_cost_snapshot.py`: dimension-level costs and optional previous-period comparison.
- `snapshot_diff.py`: offline comparison of compatible finding snapshots, preserving uncertainty for incomplete coverage.
- `agent_handoff.py`: offline validation of team plans and reports; it does not spawn agents or verify reported facts.

## Adaptive agent teams

The main agent chooses an initial team and adds or reuses workers during a task when new independent work or useful review justifies the extra context. Routine scaling decisions do not require user prompts within the authorized scope and limits. All descendants share a ceiling of 20 concurrent subagents, excluding the main agent, and lower runtime limits still apply.

Small tasks stay direct. Workers receive focused context and share fresh evidence; completed checks are reused unless a change, failure, or freshness concern requires another check. Final responses report actual distinct agent participation, with reused workers counted once and incomplete outcomes disclosed. Token savings are not guaranteed or claimed without measurements.

Example: "Use DevOps Doctor to investigate this incident read-only. Choose the initial team and scale it as useful work grows, up to 20 within available capacity."

Installing this plugin does not change the host's global agent or model settings. The [plugin guide](plugins/devops-doctor/README.md#agent-and-subagent-workflows) explains the separate host capacity setting.

## Validation

Python 3.10+ is required for the helpers. From the repository root:

```bash
cd plugins/devops-doctor
python -B tools/validate_release.py
```

Validation checks manifests, skill references, Python syntax, CLI help, and 110 offline regression tests. It does not contact AWS or GitLab. Partial collection exits 1 and failed/invalid collection exits 2; inspect findings even when collection completes with exit 0. Cost amounts use decimal strings.

## Safety

This plugin does not include secrets or credentials. It expects users to authenticate local tools such as `aws`, `glab`, `kubectl`, or `terraform` themselves.

For production work, review proposed changes before approval and run the smallest relevant validation command before rollout.
