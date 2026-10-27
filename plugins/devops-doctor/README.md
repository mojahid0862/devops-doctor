# DevOps Doctor 0.3.5

Read-only diagnostic skills and Python helpers for GitLab and AWS, plus offline Terraform, repo, and saved-finding reviews.

## Requirements

- Python 3.10+; helper runtime and tests use the standard library only.
- `glab` for GitLab reads; existing authenticated host/project context. No alternate GitLab transport is used.
- AWS CLI v2 for cloud reads; existing least-privilege profile and explicit region.
- Optional local Git, Terraform, kubectl, Docker, and Helm. Only requested readiness scopes are probed.

Run examples from this plugin directory. When operating inside another repo, invoke the helper by its absolute path and pass `--root` explicitly for repo scans. Never copy credential values into command arguments or this package.

## Faster scoped operation

```bash
python scripts/devops_doctor_preflight.py --scope local
python scripts/devops_doctor_preflight.py --scope gitlab
python scripts/devops_doctor_preflight.py --scope aws --profile dev --region ap-south-1
python scripts/aws_stack_snapshot.py --profile dev --region ap-south-1 --services rds,elasticache --max-workers 4 --output work/stack.json
python scripts/repo_devops_scan.py --root /path/to/repo --max-files 10000 --output work/repo.json
```

Preflight defaults to local. Stack service collection defaults to 4 workers; S3 details default to 20 buckets, with partial coverage reported. Repo scans prune dependency/build directories before walking their contents and skip files over 2 MiB. Limits are explicit, not silent success.

## GitLab review

```bash
python scripts/gitlab_mr_fast_review.py --repo group/project --mr-iid 44 --max-pages 5 --output work/mr.json
python scripts/gitlab_pipeline_snapshot.py --repo group/project --pipeline-id 123 --job-id 456 --output work/pipeline.json
```

Read the actual diff. Pattern scores are triage hints; no score grants merge readiness. Missing, running, or pending CI and incomplete evidence leave review blocked. Current-SHA evidence is required. Pagination is bounded and independent reads are concurrent after authentication.

## New cost and drift workflows

```bash
python scripts/aws_cost_snapshot.py --profile dev --days 14 --group-by SERVICE,REGION --compare-previous --output work/cost.json
python scripts/aws_cost_snapshot.py --profile dev --start 2026-10-01 --end 2026-10-15 --service "Amazon Simple Storage Service" --group-by USAGE_TYPE,OPERATION --output work/s3-cost.json
python scripts/snapshot_diff.py --before work/baseline.json --after work/current.json --output work/drift.json
```

Billing end dates are exclusive; default periods use completed UTC dates. Cost amounts are decimal strings, retain currency and estimated flags, and can compare an equal-length previous interval. Cost collection follows pagination explicitly.

Drift compares recorded findings, not all infrastructure settings. Account, region, collector, and filters must match. A partial snapshot cannot establish resolution. Keep the collector/ruleset version identical between baseline and current runs.

## Output and compatibility

All helpers emit sanitized JSON with `schema_version: "2.0"`, `status`, and `collection.complete`. Exit 0 means collection/analysis completed, 1 means partial, and 2 means failure or invalid input. Completion does not mean no security issues: always inspect findings. Scripts calling v0.1 should handle the new nonzero partial/failure exits and decimal-string cost amounts.

The sanitizer covers structured secret fields, environment values, credential URLs, common authorization formats, and embedded JSON. It cannot identify every possible private value; collect minimal allowlisted evidence. No persistent credential/readiness cache is introduced. Raw Terraform plans must remain in a protected temporary location and must not be committed or uploaded.

## Agent and subagent workflows

Token efficiency is the default: load relevant context on demand, reuse fresh evidence, keep tool output and reports focused, and avoid repeating completed checks without a reason. Small tasks stay direct. Workers receive bounded assignments and file references; isolated context is preferred when the assignment is self-contained. Scale the team only when the expected speed or review benefit justifies its additional context. Required evidence, validation, and blockers remain visible. This reduces avoidable token use but does not impose a hard token cap or guarantee savings; actual usage is reported only when the runtime supplies it.

Use `$devops-team` when you want parallel specialists. One main agent chooses how many subagents the task needs, up to 20, within your budget and actual runtime capacity. Twenty is a ceiling, not a requirement to create twenty workers for every task. Six reusable role templates cover runtime investigation, delivery review, security/IaC review, cost analysis, local implementation, and independent verification; multiple workers can use a role for distinct scopes. All descendants share the same 20-worker budget, excluding the main agent. Ready tasks refill free slots without waiting for an entire batch; dependencies and exclusive file ownership still apply.

The main agent estimates a useful starting team, then reassesses after progress, newly discovered work, blockers, or material delays. It can grow from, for example, 3 to 5 workers during the same task when two independent assignments become ready, without requiring a separate user request. It reuses idle workers, safely splits large assignments, and reduces the team when work finishes. A slow external job, missing access, or rate limiting does not justify duplicate workers. This adaptive behavior is implemented in the coordinator skill instructions using native host tools; the offline helper is not a background scheduler.

The main agent makes routine team-sizing and scaling decisions autonomously within the authorized task and limits; you do not need to choose a count or approve each increase. The final response always shows actual participation, for example `Agents used: 1 main + 5 subagents = 6 total`. It counts each confirmed worker once, including descendants, even when reused; planned, failed-to-start, or simulated workers do not inflate the count. Worker failures or partial results remain visible. This total covers the task, not necessarily simultaneous execution; an unverified count is reported as unverified.

Example prompts:

- "Use $devops-team to investigate these ECS 502s with runtime and log specialists. AWS read-only; do not deploy."
- "Use $devops-team to review this MR with correctness and security reviewers, sharing one current-SHA diff and CI snapshot."
- "Use $devops-team to implement the approved local fix, then have an independent agent verify it. Do not push."
- "Use $devops-team for this task. Estimate the initial team, then add subagents as useful work grows or can be split, up to 20 within available host capacity."

Native host tools do the actual spawning and coordination. The plugin does not add a separate runtime, persistent workers, credentials, paid API integration, or background monitoring. When subagent tools are unavailable, it states that and uses sequential checks unless independent agents are required.

The host limit is separate from the plugin. Local Codex documents `agents.max_concurrent_threads_per_session` (legacy alias `agents.max_threads`) for concurrently open subagent threads, excluding the primary. A session can still expose a lower actual capacity. Changing a local configuration is not proof that an existing desktop session or a managed host has more slots. See [OpenAI's configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference) for the host setting; this plugin does not change your global configuration.

To request a ceiling of twenty subagents for a new local CLI session without changing global settings:

```powershell
codex -c agents.max_concurrent_threads_per_session=20
```

This starts a separate interactive CLI session when you run it. Confirm its actual tool capacity before delegation; it does not enlarge an already-running chat. For a persistent local setting, put `max_concurrent_threads_per_session = 20` under `[agents]` in your Codex configuration. A twenty-agent live run has not been verified; managed runtime limits may be lower.

The team assigns one owner per remote query and writable path, pins scope/SHA/plan versions, orders dependent steps, and preserves blockers and disagreements. Root handles production actions within existing user authorization. A worker's status or a majority vote is never proof of production safety.

For saved plans and handoffs:

```bash
python scripts/agent_handoff.py --plan work/team-plan.json --output work/dispatch-check.json
python scripts/agent_handoff.py --plan work/team-plan.json --reports work/runtime.json work/logs.json work/review.json --output work/team-result.json
```

The helper only validates JSON. It detects duplicate ownership, path overlaps, cycles, scope/run mismatches, missing reports, missing evidence references, incomplete reviews, failed tests, and contradictory same-scope fact values. It does not execute report commands or verify that claimed evidence is true. See the skill's references and synthetic example assets for the input contract.

Plans accept `max_workers: "auto"` by default or an integer from 1 to 20, and an optional caller-supplied `runtime_capacity`. The helper bounds plan width by 20, task count, and supplied limits. Its output records the worker ceiling and effective planning width, but neither input nor output verifies actual runtime availability. More workers can help independent substantial work; dependencies, rate limits, and coordination overhead can limit the speedup.

## Validate

```bash
python -B tools/validate_release.py
python -B tools/benchmark_offline.py
```

Validation checks manifests, skill references, Python syntax, CLI help, and offline regression tests. The benchmark uses mocked delays; it is not an AWS/GitLab production latency measurement. No live cloud changes are part of validation.

## Installation and rollback

Use the packaged manifests and skills with the Codex plugin installer. For an existing local `devops-doctor@personal` entry, back up the registered source directory, replace its package contents, then run `codex plugin add devops-doctor@personal`. Open a new chat to load the updated skill instructions. To roll back, restore the previous source package and reinstall that same entry.

Public publishing is a separate action; this release does not publish or push a repository.

Design references: [OpenAI skill guidance](https://developers.openai.com/plugins/build/skills) and [native multi-agent coordination](https://developers.openai.com/api/docs/guides/responses-multi-agent). Runtime availability is checked in the active host; no API configuration is changed by this plugin.
