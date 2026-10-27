---
name: devops-operator
description: Coordinate a multi-step GitLab and AWS investigation from chat, selecting scoped evidence collectors and tracking unresolved questions. Use when the user asks for end-to-end triage or delegated operations across multiple services.
---

# DevOps Operator

Read [the evidence contract](../devops-doctor/references/evidence-contract.md). Resolve `<plugin-root>` from this file's absolute path.

For an explicit agent/subagent request or useful independent workstreams, use `$devops-team` for scoped dispatch and handoff review. Estimate the initial useful team, then reassess during the task and add workers when new or splittable independent work justifies them, within the shared 20-worker and runtime limits. Keep dependent steps ordered.

1. Identify the failure domain and known scope. Use the routing table in `$devops-doctor` only if the correct specialist is unclear.
2. Reuse verified readiness for the current investigation. If needed, run `python "<plugin-root>/scripts/devops_doctor_preflight.py" --scope gitlab` or `--scope aws --profile <profile> --region <region>`. Default `--scope local` performs no cloud/GitLab auth calls. Do not invoke unrelated tools or duplicate a helper's built-in auth check.
3. Use one narrow collector first: MR fast review, failed pipeline, ECS deployment, or an explicit AWS service list. Parallel reads must remain bounded; stop the blocked branch on missing auth/permissions.
4. Inspect `status`, `collection.complete`, `blockers`, findings, and scope before drawing a conclusion. Use exact time windows and identifiers for follow-up reads.
5. Build a timeline for incidents, separating deployment, target-health, task-stop, application-error, and alarm timestamps. State any unproven connection.
6. Complete authorized local fixes and their validation. For an additional production mutation, prepare the exact command/diff, blast radius, rollback, and health checks before requesting the remaining authorization.

Return the answer first, then decisive evidence, unresolved blockers, and the smallest next action. Include `Agents used: 1 main + N subagents = T total`, counting distinct confirmed participants in this task, including descendants and counting reused workers once; use zero subagents for direct work and state uncertainty if participation cannot be verified. Do not fill an empty report template. End with `Changed | Validate | Next` when appropriate.
