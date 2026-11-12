# Avoid repeated investigation work

Use for substantial investigations, ad hoc CLI reads or clipped evidence; preserve security review, authorization, provenance and validation. [DevOps Team](../../devops-team/SKILL.md) owns coordination; workers need only their scoped rules and evidence pointers.

## Evidence reuse and bounded reads

- Keep receipts in existing task notes/handoffs: host/project/revision or resource/window, query, evidence location, completeness and observation time; source receipts also identify filename, blob and read ranges. Reuse only when these satisfy the claim. Refresh changed scope/identity/revision, stale mutable state or discrepancies. Successful empty results count; changing executable alone does not invalidate them. Failed/incomplete/stale reads cannot prove coverage.
- Before downloading source, verify available local Git origin/ref against established identity/receipt and required commit/objects. Read immutable objects or matching worktree files; a clean tree alone proves neither remote nor deployed revision. Do not fetch each file again solely for provenance. Refresh mutable head/deployment/status/auth as required; unresolved identity stays provisional/blocked.
- Compare copied/regional source by immutable blob hash. Analyze identical bytes once for the same question, retaining path/revision mappings; inspect distinct routes, callers, imports, configuration and deployment wiring separately. Different hashes need scoped diffs/reads. Similar names prove nothing; an independent reviewer still derives conclusions from raw evidence.
- Batch independent scoped reads/parsing. Return allowlisted status/counts and decisive excerpts, preserving empty/error/partial/pagination/truncation markers. Save bulky sanitized evidence once and share receipts/retrieval pointers. A preview is not complete coverage; verify decisive findings centrally without repeating whole investigations.
- Relay textual tool output once, without embedding it inside another JSON string. With `functions.exec`, separate a shell result's metadata from its already-sanitized text: `const {output, ...metadata} = await tools.exec_command(args); text(metadata); text(output);`. Preserve exit/session/error/truncation information and stderr; apply the same separation to each successful parallel result and report any rejected call. Do not dump result objects containing large text bodies or repeatedly parse/stringify excerpts. This removes escaping and envelope duplication without altering evidence or coverage.
- Index relevant symbols/routes/fields with `rg -n` or pinned `git grep -n`, then read complete relevant functions, guards and needed callers in disjoint windows. Expand through dependencies as proof requires; do not impose arbitrary line caps or repeat whole-file dumps. For schemas, cover complete relevant fields, validators/defaults, hooks and serialization definitions. Indexes locate code; they prove neither absence nor complete coverage.
- Select large-JSON fields before returning them; retain required full evidence in protected storage and read omitted context in disjoint ranges. After truncation, narrow/split the read instead of repeating it with a smaller output allowance.
- Reuse project tests/harnesses after checking source revision, imports/globals, meaningful assertions, side effects, isolation and cleanup. Share these receipts, not a prior answer key. Prior passes do not replace independent analysis or validation after changes. Extend missing coverage, repair harness failures and rerun affected checks; preserve security assertions and inspect changed behavior before claiming success.

## Pinned-source reader

Use bundled [source_slice.py](../../../scripts/source_slice.py) for large/batched pinned-source reads after locating ranges. Resolve `<plugin-root>` from the installed skill, preserve repository cwd, and use absolute checkout/request paths:

```powershell
python -B "<plugin-root>/scripts/source_slice.py" --root "<checkout-root>" --revision <full-commit-SHA> --request "<request.json>" --format compact
```

Request JSON: `[{"path":"src/handler.py","start":10,"end":40}]` (repository-relative paths, inclusive lines). Prefer `--format compact` for human/model reads: source lines become `[number,text]` or `[number,text,true]` when redacted; absent third values mean false. The JSON envelope retains source, metadata, errors and gaps with a `format: compact` marker. Default verbose JSON remains unchanged for machine consumers.

Track requested/delivered/remaining ranges and revision/blob metadata; overlaps in one response are deduplicated. Follow remaining ranges and newly required context until coverage is complete. `--max-chars` bounds one response, never investigation coverage: increase it for a necessary complete line or split ranges without losing context. `complete` means delivery, not review/provenance completion. Resolve required errors, redactions and undelivered ranges safely; retain gaps explicitly. Keep range pointers in the canonical result/existing notes; the helper has no cross-run reuse ledger.

## Concise reporting without lost meaning

State each finding once with evidence and implication in a canonical message/table or required report; reference or merge it downstream. Follow-ups contain changed/new facts, gaps/blockers and pointers. Extra reports, provenance indexes, checklists or generated formats need a required consumer or distinct verification purpose; no mandatory extra artifacts.

Expand for correctness: preserve negative findings/controls, exact code/commands/errors/identifiers/numbers/units, negations, scope, ordering, uncertainty, authorization and validation. Do not compress raw originals or user requests, or cap required findings. Shorter representation does not prove lower tokens/cost/time; compare recorded coordinator-plus-worker usage, cache categories, retries and completed coverage.

## GitLab CLI invocation

Use `glab` only with verified host/auth; missing authentication stops the branch. Check local `glab api --help` when flags are uncertain. Do not assume GitHub flags such as `--jq`; parse JSON locally.

A Windows `glab.cmd` wrapper may interpret `&` in query strings. For ordinary safe values, use explicit GET and separate literal fields:

```powershell
glab api --method GET projects --raw-field 'search=example' --raw-field 'simple=true' --raw-field 'per_page=100' |
    ConvertFrom-Json | Select-Object id, path_with_namespace
```

Keep `--method GET`: fields can change the default method. Prefer literal `--raw-field`; typed `--field` may interpret values/read `@files`. Preserve host, pagination and scope; never concatenate user shell syntax. Separate fields cannot make arbitrary metacharacters safe through batch wrappers. Use an explicitly selected native `glab` executable with verified matching host/auth, or report the invocation blocker; do not switch credentials/transports to bypass it.
