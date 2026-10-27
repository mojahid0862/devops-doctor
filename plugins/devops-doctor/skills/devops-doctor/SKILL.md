---
name: devops-doctor
description: Route broad backend health checks and cross-service DevOps investigations involving GitLab delivery, AWS incidents, infrastructure cost, security, or Terraform. Use for requests to check all backends or multiple resource types; use the narrower specialist directly when the failure domain is already clear.
---

# DevOps Doctor

Read [the shared evidence contract](references/evidence-contract.md). For a broad backend health request, route to `$devops-team` before detailed collection, even when the user never says "agents". Otherwise choose the narrowest useful specialist; do not load every skill or run a full inventory for a narrow incident.

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
3. Fetch the smallest useful evidence set. For broad backend checks, the main agent discovers and shares a shallow resource map, assigns independent resource groups to native subagents, and combines their health reports. Start dispatch as groups become ready; do not finish every resource check before delegating. Use direct work for small scopes and state the specific limitation when workers are unavailable. Concurrent API calls alone do not count as subagents.
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
