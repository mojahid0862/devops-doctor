# DevOps Doctor 0.3.24

Read-only diagnostic skills and Python helpers for GitLab and AWS, plus offline Terraform, repo, and saved-finding reviews.

## Requirements

- Python 3.10+; helper runtime and tests use the standard library only.
- `glab` for GitLab reads; existing authenticated host/project context. No alternate GitLab transport is used.
- AWS CLI v2 for cloud reads; existing least-privilege profile and explicit region.
- Optional local Git, Terraform, kubectl, Docker, and Helm. Only requested readiness scopes are probed.

Run examples from this plugin directory. When operating inside another repo, invoke the helper by its absolute path and pass `--root` explicitly for repo scans. Never copy credential values into command arguments or this package.

## Compatible reader updates

Version 0.3.20 adds explicit local-evidence packing and bounded retrieval for saved artifacts through `scripts/evidence_slice.py`. Full originals remain unchanged; source digests, coverage and errors remain visible. See [Caveman adoption and limits](CAVEMAN-ADOPTION.md) for pinned implementation evidence, actual integration boundaries and validation scope. This is an invoked helper, not automatic host-wide compression.

Version 0.3.19 adds direct `--range 'path:start:end' --format text` source reads. Numbered sanitized text carries complete identity, redaction, error and coverage metadata, so workers need no request-file or JSON-rendering wrappers. `--max-bytes` bounds the complete UTF-8 packet; `--max-chars` remains an alias. Default and compact JSON interfaces remain supported. Use `--help` for the interface and preserve required source coverage; actual time/token improvements require matched runtime measurements.

Version 0.3.18 retains the stable 0.3.15 coordination policy. Fresh-task policy experiments did not establish lower uncached input, output and elapsed time together and are not enabled. The reader adds opt-in `--format compact` with identical coverage metadata, and masks complete recognized secret assignments including fallback expressions. Default JSON remains compatible; fewer serialized bytes are not a runtime token-savings claim.

## Faster scoped operation

Reduce repeated transfers and generated text: reuse verified immutable source, complete scoped collection receipts and compatible safe tests; refresh changed or mutable evidence. Each worker keeps one canonical result, and the coordinator reads decisive evidence and links supporting detail instead of generating duplicate report/provenance formats. Required coverage and validation remain unchanged.

Reports use concise natural language, one statement per finding, and follow-ups limited to new facts. Large evidence stays in sanitized local artifacts with precise retrieval references; status and coverage gaps remain visible. This adapts ideas reviewed in [Caveman](https://github.com/JuliusBrussee/caveman/tree/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8) without importing its code, proxy, hooks, telemetry or compression runtime. Exact technical content and required validation are preserved. Output brevity alone does not establish total-token or cost savings.

The coordinator dispatches useful independent branches before deep reads or waits. Workers receive concise assignments and execute them without repeating team planning. Independent tests and review may overlap on frozen inputs; durable handoff files are optional when useful. Performance comparisons must measure actual execution overlap, elapsed time, and available coordinator-plus-worker token totals. More workers do not guarantee less time or fewer tokens.

For substantial work, first split independently executable scopes and batch trivial or tightly coupled checks. Initial width is the minimum of ready packages, free native slots, the remaining shared 20-worker allowance, and explicit task limits, subject to real access/rate/budget constraints. Six substantial ready scopes can use six workers when capacity permits; role templates and historical worker counts do not cap the team. A general low-token preference calls for concise context and evidence reuse, not bundling a large ready workload into one or two workers. The sample handoff plan now uses `max_workers: "auto"`.

```bash
python scripts/devops_doctor_preflight.py --scope local
python scripts/devops_doctor_preflight.py --scope gitlab
python scripts/devops_doctor_preflight.py --scope aws --profile dev --region ap-south-1
python scripts/aws_stack_snapshot.py --profile dev --region ap-south-1 --services rds,elasticache --max-workers 4 --output work/stack.json
python scripts/repo_devops_scan.py --root /path/to/repo --max-files 10000 --output work/repo.json
```

Preflight defaults to local. Stack service collection defaults to 4 workers; S3 details default to 20 buckets, with partial coverage reported. Repo scans prune dependency/build directories before walking their contents and skip files over 2 MiB. Limits are explicit, not silent success.

## GitLab review

Paginated reads use explicit GET and separate literal query fields to avoid ampersand-separated pagination through Windows command wrappers. Invalid or unsafe wrapper query inputs fail before execution. For direct CLI reads, use locally supported flags and parse JSON locally; see [investigation efficiency](skills/devops-doctor/references/investigation-efficiency.md) for task-local read receipts, bounded excerpts and safe invocation. Required security checks and the selected model/reasoning setting are preserved.

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

## CloudWatch Logs Insights correlation

Run from the plugin directory with the AWS CLI and an existing credential profile.

~~~bash
python scripts/aws_log_correlation.py --profile dev --account-id 123456789012 --region ap-south-1 --log-group /aws/lambda/orders --log-group /ecs/payments --start 2026-11-13T06:00:00Z --end 2026-11-13T06:15:00Z --correlation-id trace-123 --output work/log-correlation.json
~~~

Supply at least one of `--request-id` and `--correlation-id`. Both must match when supplied together. Use explicit groups in one account and Region and an inclusive start and exclusive end. The query recognizes common top-level JSON ID fields and plain-text ID labels. It flags structured HTTP 5xx and recognized error-level signals. Other schemas, unlogged requests, and delayed ingestion can leave gaps.

Defaults are five groups, 60 minutes, 100 rows, five samples, 12 KiB of JSON, and ten polls within a 45-second CLI budget. See `--help` for bounded overrides. Samples are ordered by timestamp, favor distinct groups when space is limited, and contain report-local ID aliases in place of raw IDs. Raw log messages and AWS error bodies are excluded. Counts deduplicate usable returned rows. CloudWatch scan and match statistics are reported separately. A completed empty query means zero returned matches within the configured scope and recognized fields. Capped, unfinished, and invalid results remain partial or failed.

Reuse matching deployment, alarm, ECS, and Lambda evidence when building the timeline. The helper uses standard AWS endpoints and needs STS identity plus CloudWatch Logs `StartQuery` and `GetQueryResults`, with `StopQuery` for best-effort cleanup. Queries can incur scan charges. Result and output limits bound returned evidence, while the amount scanned depends on the selected groups and window. The report flags when a query may continue after local collection ends.

Use opaque diagnostic IDs and a profile with AWS CLI history disabled. Selectors can be visible in process arguments, shell history, AWS CLI history when enabled, and the query stored by CloudWatch.

## AWS Security Hub and GuardDuty findings

~~~bash
python scripts/aws_security_findings.py --profile dev --account-id 123456789012 --region ap-south-1
~~~

The helper verifies the expected account with STS and checks the account and Region on each finding, including results from Security Hub aggregation. This scope uses ASFF `AwsAccountId` and `Region`, OCSF `cloud.account.uid` and `cloud.region`, and GuardDuty `AccountId` and `Region`. Underlying event origin is unverified. Related resources may span accounts or Regions and retain their own location when AWS supplies it. Security Hub V2 (OCSF) is the default. Use `--securityhub-api cspm` for Security Hub CSPM (ASFF) and repeat `--service` to select sources. GuardDuty includes both active and archived findings. Keep the per-service counts separate because Security Hub can also import GuardDuty findings.

The summary reports severity counts, attack-sequence and exposure counts, service outcomes, and coverage gaps. It omits finding IDs, resource IDs, descriptions, tags, and AWS error bodies. Add `--evidence-dir <new-directory>` under a trusted local parent to save a projected `findings.json` with original finding IDs, source, account, Region, resource identities, severity, status, and timestamps. Keep that directory out of Git and shared or synced folders. This option requires Windows Python with private directory support (3.10.15+, 3.11.10+, 3.12.4+, or 3.13+) or a POSIX filesystem that enforces owner-only permissions. The collector checks CLI history locally before AWS calls and stops if history is enabled or its setting cannot be checked. GuardDuty finding IDs used in detail requests and pagination tokens can still be visible to privileged local process monitoring.

Defaults are 50 findings examined and five pages per service, 25 entries per page, a shared 60-second AWS CLI budget, and 64 KiB per emitted artifact. See `--help` for bounded overrides. The configured AWS CLI profile needs the applicable Security Hub describe and findings reads, or GuardDuty `ListDetectors`, `GetDetector`, `ListFindings`, and `GetFindings`. The collector uses standard AWS endpoints.

Complete means the requested API listing finished within its bounds. Coverage is one account and Region and depends on the services, finding retention, and integrations configured there. Review configuration, detection coverage, and individual findings separately. Empty, disabled, unavailable, and truncated collections have distinct outcomes.

## CloudFormation offline review

~~~bash
python scripts/cloudformation_review.py template --file template.yaml --guard-rules security.guard
python scripts/cloudformation_review.py change-set --file describe-change-set.json
python scripts/cloudformation_review.py events --file describe-stack-events.json --output work/cfn-timeline.json
~~~

Review the smallest saved artifact that answers the question. The helper reads local files only. Supply the original JSON response body from AWS CLI or MCP for `DescribeChangeSet` or `DescribeStackEvents` and keep pagination markers. Preserve the reviewed input and pin it with `--sha256` when reproducing a report. A missing continuation marker cannot establish that a saved export includes every page.

Template mode supports JSON with the standard library and YAML with an already available PyYAML installation. It reports literal exposure and encryption signals and flags state-retention policies for review. It leaves intrinsics, conditions, transforms, nested templates, and live settings unresolved. An installed `cfn-lint` checks a metadata-free copy with neutral configuration for templates without transforms or nested templates. An installed `cfn-guard` evaluates a supplied local rules file. Validator output is reduced to an outcome because diagnostics can echo private values. Missing tools or rules and skipped, failed, or timed-out checks are reported.

Change set mode reports AWS-recorded actions and definite, conditional, or unknown replacements. Review dependencies, backup or retention, and rollback before acting on disruptive changes. Event mode orders timestamps and links earlier failures to rollback events when an operation ID or request token matches within the same stack. These links describe timing and correlation. The report uses aliases and reason categories instead of exporting raw resource IDs, reasons, or property values.

Inputs use the shared 8 MiB limit. Supply regular files without symlinks for templates, exports, and Guard rules. Defaults are 500 items, 64 KiB of output, and 15 seconds per validator. See `--help` for bounded overrides. A partial report can still contain actionable findings.

## Output and compatibility

All helpers emit sanitized JSON with `schema_version: "2.0"`, `status`, and `collection.complete`. Exit 0 means collection/analysis completed, 1 means partial, and 2 means failure or invalid input. Completion does not mean no security issues: always inspect findings. Scripts calling v0.1 should handle the new nonzero partial/failure exits and decimal-string cost amounts.

The sanitizer covers structured secret fields, environment values, credential URLs, common authorization formats, and embedded JSON. It cannot identify every possible private value; collect minimal allowlisted evidence. No persistent credential/readiness cache is introduced. Raw Terraform plans must remain in a protected temporary location and must not be committed or uploaded.

## Agent and subagent workflows

Token efficiency is the default: load relevant context on demand, reuse fresh evidence, keep tool output and reports focused, and avoid repeating completed checks without a reason. Small tasks stay direct. Workers receive bounded assignments and file references; isolated context is preferred when the assignment is self-contained. Scale the team only when the expected speed or review benefit justifies its additional context. Required evidence, validation, and blockers remain visible. This reduces avoidable token use but does not impose a hard token cap or guarantee savings; actual usage is reported only when the runtime supplies it.

Every task, including direct specialist invocations, follows assess -> map -> dispatch -> reassess -> validate/combine. The main agent uses `$devops-team` when independent work or review benefits from workers, without requiring an explicit agents request. Small or strictly dependent tasks remain direct; unrelated tasks do not require cloud discovery. One main agent chooses how many subagents the task needs, up to 20, within your budget and actual runtime capacity. Twenty is a ceiling, not a requirement to create twenty workers for every task. Six reusable role templates cover runtime investigation, delivery review, security/IaC review, cost analysis, local implementation, and independent verification; multiple workers can use a role for distinct scopes. All descendants share the same 20-worker budget, excluding the main agent. Ready tasks refill free slots without waiting for an entire batch; dependencies and exclusive file ownership still apply.

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

Broad requests such as "check all my backends" now route directly to the [parallel health workflow](skills/devops-team/references/backend-health.md), without an explicit agents request. The main agent inventories once, assigns ready independent resource groups, reuses workers for remaining groups, and aggregates timestamped findings and uncovered resources. It reports missing worker/tool capacity rather than silently treating API concurrency as delegation. Small scopes stay direct; no fixed latency or token saving is promised.

## Validate

```bash
python -B tools/validate_release.py
python -B tools/benchmark_offline.py
```

Validation checks manifests, skill references, Python syntax, CLI help, and offline regression tests. The benchmark uses mocked delays; it is not an AWS/GitLab production latency measurement. No live cloud changes are part of validation.

The repository-root GitHub Actions workflow runs release validation on Linux and Windows with Python 3.10 and 3.12 for relevant pull requests and pushes to `main`.

MR reviews now require a collected diff version matching the MR head/base/start refs, SHA-scoped CI, and a final revision check. Missing provenance, omitted diff content, or a revision change leaves evidence partial. `raw.diff.data` now contains the version object and its `diffs` array instead of text; consumers of that raw field must adapt. Summary/status fields remain unchanged, and `evidence.diff_refs` plus `evidence.diff_version_id` record provenance.

## Installation and rollback

Use the packaged manifests and skills with the Codex plugin installer. For an existing local `devops-doctor@personal` entry, back up the registered source directory, replace its package contents, then run `codex plugin add devops-doctor@personal`. Open a new chat to load the updated skill instructions. To roll back, restore the previous source package and reinstall that same entry.

The plugin's diagnostic helpers do not publish packages or push repositories.

Design references: [OpenAI skill guidance](https://developers.openai.com/plugins/build/skills) and [native multi-agent coordination](https://developers.openai.com/api/docs/guides/responses-multi-agent). Runtime availability is checked in the active host; no API configuration is changed by this plugin.
