# Changelog

## 0.3.8 — 2026-10-27

- Apply shared task assessment, adaptive delegation, and consolidated validation to every plugin entry point, not only backend health.
- Reuse task-specific evidence across coding, reviews, CI/CD, cost, security, IaC, and incidents; preserve dependencies, authorization, host limits, and low-token direct handling for small tasks.
- Remove specialist wording that forced serial incident handling or unrelated broad inventory; share the same coordination contract across all 12 skills.

## 0.3.7 — 2026-10-27

- Route broad backend health checks to native agent teams before detailed collection, without requiring an explicit agents keyword.
- Share one shallow inventory, dispatch independent resource groups as ready, and reuse or scale workers within host limits; combine health, evidence time, and coverage gaps centrally.
- Prefer the available connected AWS read tool and bound total queries across workers. Preserve direct handling of small scopes and explicit fallback when workers are unavailable.
- Keep resource discovery separate from detailed checks; no live AWS speedup or token-savings claim is introduced.

## 0.3.6 — 2026-10-27

- Mask full secret argv values before formatting command metadata; redact quoted, escaped, multiline, and JSON-escaped CLI secrets in stdout and errors.
- Bind MR evidence to a collected immutable diff version with matching head/base/start refs and a final revision check. Missing provenance, incomplete diffs, and changed revisions leave the review incomplete.
- Move GitHub Actions validation to the repository root with read-only permissions, bounded runtime, superseded-run cancellation, and Linux/Windows Python 3.10/3.12 checks.
- Add regression coverage for reproduced redaction leaks and mixed-revision evidence. Live GitLab behavior remains separately unverified.

Compatibility: MR `raw.diff.data` is now a structured diff-version object containing `diffs`, not text. Summary/status fields are unchanged; evidence adds `diff_refs` and `diff_version_id`.

## 0.3.5 — 2026-10-27

- Prefer narrow context, focused tool output, and reuse of fresh evidence and completed checks to reduce avoidable token use.
- Include delegated context cost in autonomous team sizing; prefer self-contained worker context and concise handoffs while preserving essential instructions and required review.
- Preserve correctness, evidence completeness, and honest token reporting; no fixed savings or universal low-usage guarantee is introduced.

## 0.3.4 — 2026-10-27

- Make initial agent sizing and subsequent scaling the main agent's autonomous responsibility within existing authorization and limits, without routine user approval prompts.
- Require final reporting of the main agent and distinct subagents that actually worked on the task, deduplicating reuse and excluding planned, unstarted, historical, or simulated workers.
- Preserve incomplete worker outcomes and distinguish total participation from concurrency; report unknown participation honestly.

## 0.3.3 — 2026-10-27

- Explicitly estimate an initial team, then reassess and expand it during the task when new or splittable independent work can shorten completion time.
- Reuse idle workers, coordinate ownership transfers when splitting work, and reduce unnecessary concurrency as work completes.
- Keep delays caused by rate limits, external jobs, missing access, or dependencies from triggering duplicate workers. Retain the shared ceiling of 20 and lower user/runtime limits.

## 0.3.2 — 2026-10-27

- Set the requested team policy to one main agent with up to 20 subagents, chosen according to useful ready work, user budget, and available runtime capacity.
- Bound automatic plans at 20 and accept explicit worker budgets from 1 to 20; count all descendants together and preserve lower host limits.
- Clarify that specialist roles can be reused across distinct scopes and that a configured ceiling does not prove live execution capacity.

## 0.3.1 — 2026-10-27

- Remove the fixed three-worker package ceiling and two-worker starting limit; choose useful concurrency from ready work, user budget, and actual host capacity.
- Accept automatic or explicitly sized plans, optionally bounded by caller-supplied runtime capacity; record effective planning width without claiming verified host slots.
- Refill available slots as dependencies are satisfied, without requiring whole-batch waits. Preserve ownership, authorization, evidence, and review safeguards.

## 0.3.0 — 2026-10-26

- Add DevOps Team skill with six specialist role templates and native subagent lifecycle guidance.
- Bound delegation, separate writable paths, reuse shared reads, pin evidence scope/version, and order dependent implementation/verification.
- Add an offline plan/handoff validator for dependency cycles, ownership overlap, missing evidence, scope mismatch, incomplete reviews, and contradictory facts.
- Include synthetic handoff examples and independent skill forward-testing. No persistent agents, API credentials, production writes, or background monitoring are introduced.

## 0.2.0 — 2026-10-26

- Scope readiness to local, GitLab, AWS, or all; avoid unrelated remote auth probes.
- Concurrent independent reads; prune repo dependencies before traversal; bound collection and expose coverage.
- Central sanitized command execution, valid-JSON checking, timeouts, durations, atomic output, and explicit exit/status contract.
- Gate GitLab evidence on current commit and complete retrieval; stop on auth failures; paginate bounded lists; require real failed-job evidence for diagnosis.
- Decode Terraform IAM policy documents, distinguish ingress/egress, and compare before/after risks with conservative unknown handling.
- Add dimension-level costs, decimal currency totals, estimated flags, explicit CE pagination, and previous-period comparisons.
- Add offline comparison of compatible finding snapshots with conservative resolution rules.
- Correct ECR cross-account registry selection.
- Simplify skill routing and preserve existing user authorization for local edits.
- Add dependency-free offline tests, CLI/package checks, and a simulated performance benchmark.

Compatibility: partial/failed collection now exits nonzero; preflight defaults local; cost amounts are decimal strings. Live cloud performance and end-to-end authenticated integrations require separate validation.
