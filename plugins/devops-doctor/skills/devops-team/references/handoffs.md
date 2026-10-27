# Plan and report handoffs

The offline helper checks structure and declared ownership/completeness. It does not create agents, execute commands, fetch evidence, enforce a filesystem sandbox, or prove that reports are true. The coordinator verifies evidence and authorizations separately.

Resolve `<plugin-root>` from this skill path. Save only sanitized task metadata and results in the user's working directory. Do not include tokens, environment values, raw plans, or private payloads. Use a new `run_id` when the task scope or evidence version changes.

```bash
python "<plugin-root>/scripts/agent_handoff.py" --plan <work-dir>/team-plan.json --output <work-dir>/dispatch-check.json
python "<plugin-root>/scripts/agent_handoff.py" --plan <work-dir>/team-plan.json --reports <work-dir>/runtime.json <work-dir>/logs.json <work-dir>/review.json --output <work-dir>/team-result.json
```

## Plan

- `schema_version`: `"1.0"` for the input contract.
- `run_id`: unique ID shared by this plan and its reports.
- `scope`: nonempty object identifying the exact investigation. Include account/region/resources/window, host/project/head SHA, or plan hash as appropriate. Keep credentials out.
- `max_workers`: `"auto"` (default) or an integer from 1 to 20, excluding the coordinator and including all descendants. This is a ceiling, not the initial team size. Auto bounds plan width by task count and the 20-worker ceiling; the coordinator chooses and reassesses the useful actual count during the task, applying any smaller user budget before dispatch. Requests above 20 are rejected.
- `runtime_capacity`: optional positive integer supplied by the coordinator from the host's actual worker capacity, excluding the coordinator. The helper does not discover or verify capacity. It caps planning width by this value when present, as well as requested workers and task count; omitted capacity must still be checked at dispatch.
- `tasks`: unique `id`, a `role` string, `required` boolean (default true), `depends_on`, `read_keys`, `write_paths`, optional task-specific `scope`, and optional `review_of` task IDs.

Read keys describe a collection's identity, such as `aws:account:region:resource:window:query`. Assign each to one owner; consumers reference the produced evidence. Write paths are concrete repository-relative files/directories, with no glob, absolute path, or `..`. Overlapping paths across task owners are rejected, including case variants; transfer ownership explicitly in a revised plan after the old owner stops. A reviewer lists its reviewed tasks as dependencies.

Output `concurrency` records `requested`, `worker_limit` (20), caller-supplied `runtime_capacity` (null when absent), and `effective_plan_workers`. `ready_batches` are a static dependency plan, not mandatory synchronization barriers or proof of available agents. Refill free slots as task dependencies become satisfied; check predecessor results before dispatch. Partial evidence may support reviewing a claim, but it cannot support dependent edits requiring missing facts or make the aggregate complete.

See `assets/team-plan.example.json` beside this skill for a synthetic incident plan. Replace all synthetic scope values before use. No helper infers the intended production account.

When expanding or splitting work, revise task IDs, dependencies, and ownership before dispatch. Revalidate the saved plan when using the helper. A changed team size or reassignment within unchanged scope does not itself invalidate existing evidence or require a new `run_id`. Retained reports must still match their task ID and scope. If investigation scope or evidence version changes, use a new `run_id`, recheck retained evidence for applicability, and do not silently relabel stale reports. The helper validates the submitted plan; the main agent performs runtime reassessment and actual spawning.

## Report

Each report contains:

- `run_id`, `task_id`, exact task `scope`, `summary`, and `status`: `complete`, `partial`, `blocked`, or `failed`.
- `evidence`: items with unique `id`, `source`, timezone-aware ISO `observed_at`, and `claim`. Optional `fact_key` plus `value` allows contradiction detection within the same exact scope; use keys describing an identical resource, attribute, and observation interval.
- `findings`: unique `id`, `severity`, `summary`, `evidence_ids`, and `confidence` (`high`, `medium`, or `low`). Reference only evidence present in that report; copy a minimal referenced evidence record when consuming another task's artifact.
- `changed_files`: repository-relative paths within this task's ownership.
- `tests`: `command` and `status` (`passed`, `failed`, or `not_run`). Commands are text evidence, never executed by this helper. Include an output reference in the surrounding report/evidence for a claimed pass.
- `blockers`: unresolved issues; a report with blockers is not fully complete.
- `reviewed_tasks`: task IDs reviewed, covering the plan's `review_of` list.

See `assets/task-report.example.json` for a synthetic report. It contains no live production evidence.

## Interpretation

Missing or incomplete required reports and contradictions prevent a complete aggregate. Invalid input or failed required tasks produce failure. Compare reported facts only within matching scope; inspect different timestamps before declaring a conflict. Completion means the declared handoffs are covered, not that CI passed, a finding is resolved, or production is safe. Review the helper's blockers and conflicts, then the decisive source evidence.

The common emitter uses output schema `2.0` and exit 0 complete, 1 partial, 2 failed/invalid. This is distinct from input contract `schema_version: "1.0"`.

## Actual participation in the final response

Keep actual execution accounting separately from the plan/report validator. `effective_plan_workers`, role count, task count, and number of JSON reports do not establish how many agents ran. Use native identities and confirmed execution or returned work for the current task; deduplicate reused workers and include descendants. Do not count unsuccessful spawns or synthetic evaluation workers. Report `Agents used: 1 main + N subagents = T total`, or state that participation could not be verified. Distinct participants over the task and peak concurrent workers are different measurements; the 20-worker ceiling applies to concurrency. Briefly identify incomplete or unsuccessful outcomes when present.
