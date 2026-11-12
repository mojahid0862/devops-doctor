---
name: devops-doctor
description: Route DevOps tasks across code review, GitLab delivery, AWS incidents and health, infrastructure cost, security, and Terraform. Select relevant specialists under the shared evidence and adaptive team workflow.
---

# DevOps Doctor

Apply [the shared evidence contract](references/evidence-contract.md) once. Main agents follow [DevOps Team's canonical workflow](../devops-team/SKILL.md); assigned workers load only their scoped specialist and missing constraints. Select by the actual question, without loading every skill or collecting unrelated inventory.

| User goal | Specialist |
| --- | --- |
| All backends/account-wide health | `$devops-team` and [backend health](../devops-team/references/backend-health.md) |
| Agents/parallel specialist work | `$devops-team` |
| Multi-step GitLab/AWS investigation | `$devops-operator` |
| MR review | `$gitlab-mr-review` |
| Failed pipeline/job | `$gitlab-pipeline-doctor` |
| AWS cross-service deployment incident | `$aws-deployment-doctor` |
| ECS/Fargate tasks or target health | `$ecs-fargate-doctor` |
| Terraform plan risks | `$terraform-plan-review` |
| AWS spend/rightsizing | `$cost-optimizer` |
| Security posture/snapshot drift | `$security-drift-check` |
| Rollback/recovery plan | `$rollback-planner` |
| Logs, metrics, alarms, incident timeline | `$observability-doctor` |

Resolve the requested account/region/resource or GitLab project/MR/job and inspect relevant local configuration. Check selected-scope readiness only when unknown; reuse it until auth failure/context change. Do not preflight immediately before a helper that checks the same authentication. For a requested fix, produce the minimal patch, validation and rollback within existing authorization.

## Packaged helpers

Resolve `<plugin-root>` from this skill's absolute location (two parent directories). Preserve the user's repository cwd and invoke `python "<plugin-root>/scripts/<helper>.py"`; see each helper's `--help` for options.

- `devops_doctor_preflight.py --scope local|gitlab|aws|all`: local by default; select remote scope explicitly.
- `aws_stack_snapshot.py`: bounded concurrent collection of selected services.
- `aws_cost_snapshot.py`: dimension breakdown/previous-period comparison.
- `snapshot_diff.py`: offline comparison of compatible saved findings.
- `agent_handoff.py`: offline plan/handoff validation; never launches agents.
- `source_slice.py`: immutable-revision line ranges after symbol discovery. Prefer `--format compact` for human/model reads; default JSON remains for consumers. Follow [coverage rules](references/investigation-efficiency.md#pinned-source-reader).

Return concise findings with source/time and the team's participation/validation summary; respect the user's requested format.
