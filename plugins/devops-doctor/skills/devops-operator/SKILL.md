---
name: devops-operator
description: Coordinate a multi-step GitLab and AWS investigation from chat, selecting scoped evidence collectors and tracking unresolved questions. Use when the user asks for end-to-end triage or delegated operations across multiple services.
---

# DevOps Operator

Read [the evidence contract](../devops-doctor/references/evidence-contract.md). Resolve `<plugin-root>` from this file's absolute path.

Apply the shared assess/map/dispatch/reassess/combine lifecycle to every task, including code, CI/CD, cost, security, IaC, and incidents. Use `$devops-team` for useful independent work or review before detailed collection; no agents keyword is required. Share a task-specific map once, dispatch ready branches, then add or reuse workers as work grows within the shared 20-worker and runtime limits. For backend-wide checks, specialize this through the [backend health workflow](../devops-team/references/backend-health.md). Small tasks stay direct and dependent steps stay ordered.

1. Identify the failure domain and known scope. Use the routing table in `$devops-doctor` only if the correct specialist is unclear.
2. Reuse verified readiness for the current investigation. If needed, run `python "<plugin-root>/scripts/devops_doctor_preflight.py" --scope gitlab` or `--scope aws --profile <profile> --region <region>`. Default `--scope local` performs no cloud/GitLab auth calls. Do not invoke unrelated tools or duplicate a helper's built-in auth check.
3. For a narrow incident, use one relevant collector first: MR fast review, failed pipeline, or ECS deployment. For broad health checks, partition the shared inventory before deep reads, assign one owner per resource/query, and dispatch available workers. Use the connected read-only AWS tool when available; CLI helpers are an option when that is the configured transport. Bound aggregate reads across workers; stop blocked branches on missing auth/permissions.
4. Inspect `status`, `collection.complete`, `blockers`, findings, and scope before drawing a conclusion. Use exact time windows and identifiers for follow-up reads.
5. Build a timeline for incidents, separating deployment, target-health, task-stop, application-error, and alarm timestamps. State any unproven connection.
6. Complete authorized local fixes and their validation. For an additional production mutation, prepare the exact command/diff, blast radius, rollback, and health checks before requesting the remaining authorization.

Return the answer first, then decisive evidence, unresolved blockers, and the smallest next action. Include `Agents used: 1 main + N subagents = T total`, counting distinct confirmed participants in this task, including descendants and counting reused workers once; use zero subagents for direct work and state uncertainty if participation cannot be verified. Do not fill an empty report template. End with `Changed | Validate | Next` when appropriate.
