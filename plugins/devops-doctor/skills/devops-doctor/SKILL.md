---
name: devops-doctor
description: Route DevOps tasks across code review, GitLab delivery, AWS incidents and health, infrastructure cost, security, and Terraform. Apply shared task assessment and adaptive delegation across domains, then select the relevant specialist.
---

# DevOps Doctor

Read [the shared evidence contract](references/evidence-contract.md). Every task starts with scope/evidence assessment and a team-sizing decision. Use `$devops-team` before detailed work whenever independent branches or useful independent review justify workers, regardless of task domain or an explicit agents request. Choose the relevant specialist for each branch. Small or strictly dependent tasks stay direct; do not load every skill or collect unrelated inventory.

| User goal | Specialist |
| --- | --- |
| Check all backends, account-wide health, or multiple independent resource groups | `$devops-team` and its [backend health workflow](../devops-team/references/backend-health.md) |
| Agents, subagents, or parallel specialist work | `$devops-team` |
| Coordinate a multi-step GitLab/AWS investigation | `$devops-operator` |
| Review an MR | `$gitlab-mr-review` |
| Diagnose a failed pipeline/job | `$gitlab-pipeline-doctor` |
| AWS cross-service deployment incident | `$aws-deployment-doctor` |
| ECS/Fargate service, tasks, or target health | `$ecs-fargate-doctor` |
| Terraform plan risks | `$terraform-plan-review` |
| AWS spend, cost changes, or rightsizing | `$cost-optimizer` |
| Security posture or saved-snapshot drift | `$security-drift-check` |
| Rollback/recovery plan | `$rollback-planner` |
| Logs, metrics, alarms, incident timeline | `$observability-doctor` |

## Efficient investigation

1. Resolve the requested account/region/resource or GitLab project/MR/job. Inspect relevant local configuration; it describes intended state, not proof of deployed state.
2. Check readiness only for the selected scope when unknown. Reuse readiness within the investigation; invalidate after auth failure or a context change. Do not run preflight immediately before a helper that already checks the same authentication.
3. Build the smallest useful shared task map from existing evidence: resources, code/diff, jobs, costs, or plan changes as relevant. Assign ready independent branches to native workers and combine their findings. Reuse or add workers when new work becomes ready; do not finish the task serially before assessing delegation. Preserve dependency order, exclusive ownership, and direct handling of tiny tasks. Disclose unavailable capacity; API concurrency alone is not agent participation.
4. Correlate timestamps before assigning causality. Report observed facts, inference, incomplete coverage, and the next verification separately.
5. For a requested fix, produce the minimal patch, validation, and rollback. Existing authorization persists; production actions beyond its scope need approval.

## Packaged helpers

Resolve `<plugin-root>` from this skill's absolute location (two parent directories). Keep the user's repository as the working directory. Use `python "<plugin-root>/scripts/<helper>.py"`; do not resolve helper paths against the user's cwd.

- `devops_doctor_preflight.py --scope local|gitlab|aws|all`: default local; select remote scope explicitly.
- `aws_stack_snapshot.py`: bounded concurrent collection for selected services.
- `aws_cost_snapshot.py`: dimension breakdown and previous-period comparison.
- `snapshot_diff.py`: offline comparison of findings from compatible saved snapshots.
- `agent_handoff.py`: offline validation of team plans and evidence handoffs; it does not launch agents.
- Other specialist helpers retain their documented commands. See `--help` for exact options.

Prefer concise findings with source and time. End with `Changed | Validate | Next` when appropriate to the user's requested format.
