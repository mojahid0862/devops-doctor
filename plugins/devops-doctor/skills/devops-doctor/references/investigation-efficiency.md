# Avoid repeated investigation work

Use these mechanics for long investigations, ad hoc CLI reads, or clipped evidence. Preserve required security review, source provenance, authorization and validation.

## Evidence reuse and bounded reads

- Keep a compact in-task record of successful reads: host/project/revision or resource/window, query, result/evidence location, and collection time. A successful empty result is also evidence. Repeat only for changed scope, identity, revision, freshness, or a discrepancy; changing executables alone does not invalidate a successful read. Do not reuse failed, incomplete or stale collection as complete evidence.
- Batch independent scoped reads and local parsing into one tool call when possible. Return allowlisted status/counts and exact decisive excerpts, retaining empty/error/partial/pagination/truncation markers. Save bulky sanitized evidence once; share its path, scope/revision/window, coverage and retrieval pointers with workers. A short preview never proves complete coverage. Verify decisive findings centrally without repeating each worker's whole investigation.
- Locate symbols, routes or errors first (`rg -n`), then return bounded surrounding ranges. For large JSON, select fields before returning it. Keep the full evidence in a protected local workspace when needed, and cover omitted required context with disjoint ranges. After truncation, narrow or split the read; do not request the same large block with a smaller output allowance.
- Use the project's existing tests when suitable. Before building a focused harness, inspect the exercised imports, globals and cleanup paths so missing scaffolding is not mistaken for a product failure. Repair harness failures and rerun affected checks; retain security assertions and inspect changed behavior before declaring a pass.

## Concise reporting without lost meaning

Use clear, concise natural language. State each finding once with its evidence and implication; omit introductions, repeated plans, and repeated status. Follow-up handoffs report new or changed facts, blockers and evidence references. Expand whenever correctness requires it. Preserve exact code, commands, errors, identifiers, numbers, units, negations, scope, ordering, uncertainty, authorization and validation; never shorten these into ambiguous fragments. Do not compress raw originals or user requests. Shorter prose alone does not prove lower total tokens, cost or elapsed time; compare recorded coordinator and worker usage, cache categories, retries and completed coverage.

## GitLab CLI invocation

GitLab remote actions still use `glab` only. Reuse verified host/authentication context; missing authentication stops that branch. Check local `glab api --help` once if required flags are uncertain. Do not assume GitHub CLI flags such as `--jq` are available; parse returned JSON locally.

On Windows, a `glab.cmd` wrapper can interpret `&` in URL query strings. For ordinary safe query values, use explicit GET and separate literal fields:

```powershell
glab api --method GET projects --raw-field 'search=example' --raw-field 'simple=true' --raw-field 'per_page=100' |
    ConvertFrom-Json | Select-Object id, path_with_namespace
```

Fields can change the default HTTP method, so keep `--method GET`. Prefer `--raw-field` for literal strings; typed `--field` may interpret values or read `@files`. Preserve the intended host, pagination and scope. Do not concatenate user-supplied shell syntax into commands. Separate fields do not make arbitrary values safe through batch wrappers: for metacharacter values, use an explicitly selected native `glab` executable with verified matching host/auth context, or report the invocation blocker. Do not change credentials or transports to bypass it.
