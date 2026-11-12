# Avoid repeated investigation work

Use these mechanics for long investigations, ad hoc CLI reads, or clipped evidence. Preserve required security review, source provenance, authorization and validation.

## Evidence reuse and bounded reads

- Keep a compact in-task record of successful reads: host/project/revision or resource/window, query, result/evidence location, completeness and collection time. For source, retain filename, revision/blob ID and already-read line ranges in existing notes or handoffs, so the next read covers missing context rather than repeats it. Reuse a result only when those fields satisfy the current claim; refresh changed scope, identity, revision, freshness or discrepancies. A successful empty result is also evidence, and changing executables alone does not invalidate it. Failed, incomplete or stale collection cannot establish complete coverage.
- Before downloading versioned source, inspect available local Git source. Verify the repository origin/ref against established identity or a matching collection receipt and verify the required commit/objects. Read immutable Git objects or confirm the relevant worktree files match them; a clean tree alone does not prove the correct remote or deployed revision. Reuse this source without fetching each file again solely to create provenance. Mutable head, deployment, status and authentication state still need refresh when the claim requires it; unresolved identity stays provisional or blocked.
- For copied or regional source, compare immutable blob hashes before rereading. Analyze byte-identical source once for the same question, retaining each path/revision mapping; inspect distinct routes, callers, imports, configuration and deployment wiring separately. Similar filenames do not establish equivalence. Different hashes require a scoped diff or relevant reads; requested independent review still derives its own conclusions from raw source.
- Batch independent scoped reads and local parsing into one tool call when possible. Return allowlisted status/counts and exact decisive excerpts, retaining empty/error/partial/pagination/truncation markers. Save bulky sanitized evidence once; share its path, scope/revision/window, coverage and retrieval pointers with workers. A short preview never proves complete coverage. Verify decisive findings centrally without repeating each worker's whole investigation.
- For large files, first retrieve a line index of relevant symbols, routes or fields (`rg -n` for matching worktree files or `git grep -n` at the pinned revision), then read complete relevant functions and guards plus needed callers in disjoint windows. Size windows to the function or behavior being traced, expanding through dependencies when proof requires it; do not use arbitrary line caps or repeat whole-file dumps. For schemas, locate relevant fields, validators/defaults, hooks and serialization, then read their complete relevant definitions instead of dumping the whole schema to find them. An index locates code; it does not prove absent behavior or complete coverage.
- For large JSON, select fields before returning it. Keep needed full evidence in a protected local workspace and cover omitted required context with disjoint ranges. After truncation, narrow or split the read instead of requesting the same block with a smaller output allowance.
- Inspect available project tests and focused harnesses before creating another. Reuse them after checking the exercised source revision, imports/globals, meaningful assertions, side effects, isolation and cleanup. Prior conclusions or a previous pass do not replace independent analysis or current validation when inputs changed. Extend missing coverage rather than recreate a suitable harness. Repair harness failures and rerun affected checks; retain security assertions and inspect changed behavior before declaring a pass.

## Pinned-source reader

For large or batched pinned-source reads, invoke the bundled [source_slice.py](../../../scripts/source_slice.py) CLI after locating ranges. Resolve `<plugin-root>` from the installed skill location and preserve the repository cwd. For model/human reads, use direct numbered text and repeat inline ranges instead of writing request files or importing the helper to reformat JSON:

```powershell
python -B "<plugin-root>/scripts/source_slice.py" --root "<checkout-root>" --revision <full-commit-SHA> --range 'src/handler.py:10:40' --range 'src/guards.py:1:60' --format text --max-bytes 12000
```

Ranges use repository-relative paths and inclusive line numbers. `--request <file>` or `--request -` still accepts a JSON list such as `[{"path":"src/handler.py","start":10,"end":40}]`; it is mutually exclusive with inline ranges. Use literal/structured argument handling for unusual filenames, without shell interpolation. Default verbose JSON and opt-in compact JSON remain compatible for machine consumers.

Text packets start with `SOURCE_SLICE_TEXT_V1`, retain complete RESULT/ITEM metadata and end with `END`. A row is a line number followed by one tab and sanitized source; suffix `R` marks redaction, `J` means the following text is a JSON string for control-safe escaping, and `RJ` means both. Split only the first tab; ordinary quotes, backslashes and whitespace remain source text. In `functions.exec`, relay the tool's text once rather than JSON-encoding the entire result again: `const {output, ...metadata} = await tools.exec_command(args); text(metadata); text(output);`. Keep all status, stderr, session and truncation information, including rejected parallel calls.

Use `--help` for the documented interface. Read or modify the helper implementation only when debugging or changing the helper; do not rediscover its API in every source-review worker. Select only assigned identities/fields from task maps instead of dumping every repository/resource index into each worker.

The response identifies revision/blob and requested, delivered and remaining ranges; overlapping ranges within one response are deduplicated. Follow remaining ranges and newly required context until coverage is complete. `--max-bytes` (legacy alias `--max-chars`) bounds one UTF-8 response including framing, not the investigation. Increase it for a necessary complete line or split ranges without losing context, and allow enough outer tool output for the packet. A missing END marker or any host truncation warning leaves text delivery incomplete. `complete` means delivery, not review/provenance completion. Preserve and resolve required errors, redactions and undelivered ranges. Keep read-range pointers in canonical results/existing notes; there is no cross-run reuse ledger.

## Concise reporting without lost meaning

State each finding once with its evidence and implication in a canonical message/table or required report. Reference or merge it downstream instead of regenerating the same detail in reports, provenance indexes, status checklists or artifact-generation code. Follow-ups report new or changed facts, blockers and evidence pointers. Create additional formats only for a required consumer or a distinct verification need. Expand whenever correctness requires it; preserve negative findings, exact code, commands, errors, identifiers, numbers, units, negations, scope, ordering, uncertainty, authorization and validation. Do not compress raw originals or user requests. Shorter prose alone does not prove lower total tokens, cost or elapsed time; compare recorded coordinator and worker usage, cache categories, retries and completed coverage.

## GitLab CLI invocation

GitLab remote actions still use `glab` only. Reuse verified host/authentication context; missing authentication stops that branch. Check local `glab api --help` once if required flags are uncertain. Do not assume GitHub CLI flags such as `--jq` are available; parse returned JSON locally.

On Windows, a `glab.cmd` wrapper can interpret `&` in URL query strings. For ordinary safe query values, use explicit GET and separate literal fields:

```powershell
glab api --method GET projects --raw-field 'search=example' --raw-field 'simple=true' --raw-field 'per_page=100' |
    ConvertFrom-Json | Select-Object id, path_with_namespace
```

Fields can change the default HTTP method, so keep `--method GET`. Prefer `--raw-field` for literal strings; typed `--field` may interpret values or read `@files`. Preserve the intended host, pagination and scope. Do not concatenate user-supplied shell syntax into commands. Separate fields do not make arbitrary values safe through batch wrappers: for metacharacter values, use an explicitly selected native `glab` executable with verified matching host/auth context, or report the invocation blocker. Do not change credentials or transports to bypass it.
