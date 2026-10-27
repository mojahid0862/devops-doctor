# Specialist roles and team patterns

These are task roles instantiated with the host's native subagent tools, not installed models, background services, or additional permissions. The coordinator remains responsible for scope and the final result.

One main agent may coordinate up to 20 subagents across these roles, using only as many as the task needs and the runtime permits. Repeat a role for independent scopes when useful; the six templates are not a six-worker cap. Prefer direct work for tiny tasks and keep dependent steps ordered. The 20-worker budget includes every descendant together.

| Role | Skill/context to provide | Assignment and return |
| --- | --- | --- |
| Runtime investigator | `ecs-fargate-doctor`, `aws-deployment-doctor`, or `observability-doctor` | Answer one runtime hypothesis from a bounded resource/time window. Return observed timestamps, health signals, and causality gaps. |
| Delivery reviewer | `gitlab-mr-review` or `gitlab-pipeline-doctor` | Review one diff concern or failed job through glab-only evidence, pinned to project/host/SHA. Return file/line or trace references and CI completeness. |
| Security/IaC reviewer | `security-drift-check` or `terraform-plan-review` | Review the supplied configuration/plan for concrete risk. Distinguish intended/deployed state and unknown values. Never echo raw secrets. |
| Cost analyst | `cost-optimizer` | Explain a cost dimension or utilization hypothesis within one billing scope. Preserve currency, estimated flags, and attribution limits. |
| Local implementer | Assigned repo files plus relevant specialist | Make the authorized minimal patch within exclusive paths. Return diff summary, tests, rollback, and unresolved issues. No production mutation. |
| Independent verifier | Frozen evidence/diff and acceptance criteria | Challenge the result, inspect missing proof and regressions, and run allowed focused checks. Return verified facts and remaining blockers. Do not rely solely on another agent's summary. |

## Incident

- Runtime investigator: service/task/target health and deploy timestamps.
- Observability investigator: one precise log/metric hypothesis using the same UTC window.
- Coordinator correlates the returned timeline. A verifier checks any proposed causal claim before a material production recommendation. A deployment happening nearby is not causation.

## Large merge request

The coordinator or designated collector fetches one current-SHA metadata/diff/CI set. Delegate separate correctness/delivery and security/performance concerns against that same artifact. Required CI remains unverified while pending, regardless of reviewers' conclusions. One owner applies any authorized patch; verification follows that patch.

## Cost investigation

One owner fetches billing totals/dimensions; a second fetches only relevant utilization/configuration evidence. Avoid two broad inventories. Analysts share the account, period, service filter, metric, and currency; technical data is not automatically proof of financial savings.

## Terraform change

Use one protected plan artifact and its content hash. Split destructive/lifecycle review from IAM/network review. Neither worker runs apply or regenerates the plan unnoticed. The coordinator resolves discrepancies and checks scope/unknowns before proposing a rollout.

## Task message template

```text
Task ID / question:
Scope and evidence version:
Relevant skill absolute path:
Existing user constraints and authorization:
Owned remote read keys / writable paths:
Inputs / dependencies:
Allowed validation / stopping condition:
Return: findings, evidence refs and time, confidence, blockers, changed files, tests run.
```

When scope spans AWS and GitLab, keep each task's explicit scope in its handoff. Claims from different scopes must not be collapsed into one fact. Reviewers should cite which task outputs and versions they reviewed.
