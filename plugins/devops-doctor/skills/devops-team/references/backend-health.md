# Broad backend health workflow

Use native agents for independent backend health checks; preserve read-only authorization and the shared evidence contract. Small or strictly dependent checks stay direct. Keep the map and ownership in concise messages/tables; no separate planning artifact is required.

## Establish scope and inventory once

The main agent owns inventory. Resolve the authorized account, regions, environment, and backend from supplied context, deployment references, or scoped live discovery. Confirm execution identity once through the selected access path; share the evidence. Do not enumerate unrelated accounts/regions or treat every account resource as part of the backend.

Set one UTC window: the requested incident interval or a stated recent interval such as the last 60 minutes. Record snapshot collection times separately. Carry the same account, region set, and window into every assignment; workers must not silently widen scope or change credentials.

Build a shallow map of resource IDs/types, regions, membership evidence, dependencies, and coverage/gaps. Reuse fresh task inventory. Configuration and screenshots are discovery leads, never proof of current health. Fetch enough metadata to identify relevant compute/ingress, stores/cache, and asynchronous dependencies. Bound and paginate lists; record caps, denied reads, and unresolved membership.

Dispatch each group once its resources and inputs are known, before deeper main-agent reads or a wait; continue scoped inventory while checks run. Do not wait for complete account discovery or another group's result. Workers consume the shared map and return new dependencies to the main agent for ownership and follow-up.

## Partition work and dispatch

Group coupled resources and batch compatible reads; avoid a worker per API call, metric, or small resource. Size assignments by expected work and independent questions. These categories describe coverage, not a fixed three-worker allocation:

| Group | Owned health checks |
| --- | --- |
| Compute and ingress | ECS/EC2 or other deployed compute, task/instance status, deployments, associated target groups/load balancers, capacity and request/error/latency metrics |
| Data and cache | Relevant RDS/database and cache status/events, connectivity indicators available from existing telemetry, connections, latency, errors, CPU/memory and capacity metrics |
| Asynchronous processing | Relevant Lambda, queues/DLQs and workflows: runtime state, invocation/execution failures, throttles, backlog/age and duration metrics |

Split oversized groups by independent service, region, or investigative question; merge small groups. Rebalance when one group contains most of the ready work, with read ownership transferred before dispatch. Assign shared dependencies one owner. Include other critical dependencies only when they belong to the requested backend.

Start with useful ready groups, bounded by 20 concurrent subagents including descendants and any lower user/host limit. Subtract the main agent if included in host capacity; account for occupied slots. Choose and briefly state the initial count autonomously. Use native tools, never chats or separate Codex processes. If delegation is unavailable, check sequentially and disclose why.

Handoff: question; resources/window; map/evidence references; relevant skill path; user/read-only/secrecy constraints; owned reads; required signals; stopping condition; return format. Prefer isolated context. Workers use inherited AWS connector access when available and sufficient; do not force CLI or pass credentials into prompts. Missing/failed access returns an exact blocker. If only the main agent has access, transfer read ownership to it and return sanitized evidence to workers for analysis. Report actual collection concurrency separately from parallel analysis; one collector may batch independent reads. Otherwise report blocked coverage. Authorized alternatives retain the verified scope.

Track read keys as `account:region:resource:signal-or-query:window`, including underlying keys in batched calls. Inventory and health reads differ; each collection has one owner, including the main agent. Consumers/reviewers reuse sanitized evidence. The main agent can finish inventory or own distinct checks. Transfer ownership before reassignment; never duplicate worker reads.

## Check health, then investigate anomalies

Check both current operational state and relevant metrics across the window. Active resources, green alarms or absent error logs alone do not prove health. Include traffic and datapoint coverage; missing metrics or no activity cannot demonstrate end-to-end success. Compare applicable thresholds, configured limits, or a stated baseline without inventing universal cutoffs.

Use targeted events/logs for anomalous states/metrics/alarms or user-specified symptoms. Bound reads by resource, stream, route/error and interval; inspect truncation. Follow up on discrepancies and preserve causality limits. Do not dump every resource's logs, generate production traffic, or remediate without applicable authorization.

Reassess ready/running/blocked/completed work after results, new dependencies, blockers or material delays. Reuse compatible idle workers first; add workers for useful independent work within limits. Dispatch ready groups without waiting for the slowest group. Split assignments only after owners relinquish transferred reads. Rate limits/access failures/external waits do not justify duplicate workers. Release obsolete work and briefly report meaningful size changes.

## Return and reconcile coverage

Workers return a compact table or equivalent fields:

```text
Task / account / region / resources / UTC window / observed_at:
Collection: complete | partial | blocked | failed
Health by resource/signal: healthy | degraded | critical | unknown | blocked
Decisive state + metric values, units, datapoint/traffic coverage, evidence refs:
Anomaly findings / confidence / targeted follow-up results:
Checked keys / unchecked keys / blockers / newly found dependencies:
Changed paths and actual tests or probes (none when none):
```

Separate collection completeness from health. The main agent unions unique checked resource/signal/window keys against the map and required signals; list uncovered checks and unresolved discovery. Deduplicate shared dependencies instead of adding worker totals. Capped inventory, missing checks or stale evidence prevent complete coverage claims; healthy subsets do not hide gaps.

Inspect decisive evidence; resolve contradictions by scope/time and narrow verification. Return one assessment with affected resources, evidenced impact, coverage/gaps, and next action. Unknown/blocked evidence remains so. Report actual native participants as `Agents used: 1 main + N subagents = T total`; reuse counts once, planned roles/failed spawns do not count. End with `Changed | Validate | Next`.
