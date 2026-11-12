# Caveman adoption: implementation and limits

Reviewed Caveman 4.1.0 at commit `3dc497a7f858c774d6e15b25e8c6120ef3a0eda8`, verified against its GitHub HEAD on 2026-11-12. DevOps Doctor 0.3.12-0.3.19 had adopted concise reporting and bounded source reads. That was partial adoption; it did not install Caveman's input-compression runtime.

## Source-backed changes in 0.3.20

| Verified upstream technique | DevOps Doctor adoption |
|---|---|
| [Exact adjacent repetition](https://github.com/JuliusBrussee/caveman/blob/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8/engine/compressors/repetition.go#L24-L85): compare identical lines, preserve distinct order, reject a larger representation | New `evidence_slice.py lines --pack-runs` for saved local evidence. Compare original lines before redaction, preserve line ranges/counts and EOL, and choose packing only when its complete packet is smaller than the ungrouped packet. |
| [Recovery before lossy output](https://github.com/JuliusBrussee/caveman/blob/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8/engine/engine.go#L98-L143) and [whole-record retrieval with visible gaps](https://github.com/JuliusBrussee/caveman/blob/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8/engine/retrieve_query.go#L59-L111) | Keep the supplied artifact unchanged; emit its digest, requested/delivered/remaining selections and explicit errors. Later reads can require the same SHA-256. Exact JSON pointers/array ranges replace heuristic relevance selection. A missing selection fails instead of dumping the full file. |
| [Investigate until sufficient cause or exact blocker](https://github.com/JuliusBrussee/caveman/blob/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8/skills/investigate-first/SKILL.md) and [verify acceptance, then stop](https://github.com/JuliusBrussee/caveman/blob/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8/skills/verify-and-stop/SKILL.md) | Select each next check for an unresolved hypothesis or acceptance criterion. Stop that investigation branch after sufficient proof; finish all required independent/security checks. |
| [Reusable scripts](https://github.com/JuliusBrussee/caveman/blob/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8/README.md#blocks-code-mode-script-written-once) | Reuse compatible project/plugin helpers before generating parsing code. Check interfaces and side effects; a simpler native command remains preferable. No external Blocks runtime is installed or claimed audited. |
| [Meaning-preserving concise output](https://github.com/JuliusBrussee/caveman/blob/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8/skills/caveman/SKILL.md) and [verification of compressed absence claims](https://github.com/JuliusBrussee/caveman/blob/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8/skills/cavecrew/SKILL.md) | Retain exact facts, negations, technical payloads and uncertainty. Check coverage before reporting no issues. Use normal prose for persisted documentation and whenever short wording obscures safety or sequence. |

The helper is independently written Python using the standard library and existing Doctor sanitizers. It is explicitly invoked; a skills plugin cannot transparently rewrite every tool result. Use it on saved, already-sanitized collector artifacts. Redaction remains best effort and redacted fields remain evidence gaps. The digest proves file identity, not collection completeness or access authorization.

## Saved local evidence

For large already-sanitized collector files, use [evidence_slice.py](scripts/evidence_slice.py) and its `--help` instead of generating another parser. Examples:

```powershell
python -B "<plugin-root>/scripts/evidence_slice.py" --file "<saved.log>" --max-bytes 12000 lines --range 1:200 --pack-runs
python -B "<plugin-root>/scripts/evidence_slice.py" --file "<saved.json>" --sha256 <previous-digest> --max-bytes 12000 json --pointer /data/items --array-range 0:9
```

Lines are one-based; array bounds are zero-based, both inclusive. Retain the returned source digest for further reads. The reader accepts up to 8 MiB, 100,000 lines and 128 selections; larger/invalid inputs fail explicitly. JSON carries a named root-context allowlist, so select required nested status/error envelopes explicitly. Resolve required remaining selections/redacted gaps, and preserve collection errors and pagination alongside selected records. Complete delivery does not prove a complete collection. The helper keeps originals unchanged and does not infer relevance or collapse distinct events. Prefer a native read for already-small evidence; packet byte savings are not runtime token savings.

## Intentionally unimplemented runtime features

- Automatic Codex shell rewriting: the inspected [CLI hook](https://github.com/JuliusBrussee/caveman/blob/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8/packages/cli/src/index.ts#L17424-L17429) exits unchanged for Codex shell tools. Its profile's declared hook is insufficient evidence of working interception.
- Proxy/provider integration: the [Codex wrapper](https://github.com/JuliusBrussee/caveman/blob/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8/packages/cli/src/index.ts#L8334-L8397) changes the child Codex home, provider/auth configuration and runtime routing. No such integration was installed or claimed tested in Codex Desktop.
- Cloud model routing and provider cache changes: these belong to a separate runtime and can involve outgoing context. Doctor preserves the selected model, native agent policy and existing authentication/configuration.
- Lossy source-body, stack-frame, JSON/log relevance filtering: these can remove decisive security evidence. Doctor uses explicit selections and exact repeated-line packing; omitted required evidence must be retrieved before concluding.

No user prompts, memory files, source code, global hooks or model settings are rewritten by this adoption.

## What the numbers establish

Caveman's own [Honest Numbers](https://github.com/JuliusBrussee/caveman/blob/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8/docs/HONEST-NUMBERS.md#what-the-response-skill-does) distinguishes response style from input compression. Its published [session benchmark](https://github.com/JuliusBrussee/caveman/blob/3dc497a7f858c774d6e15b25e8c6120ef3a0eda8/docs/WRAP-BENCHMARK.md) uses synthetic fixtures, a different host/model, and sums uncached plus cache-read/write input. The raw harness/results are not available in that checkout; its newer per-file shrinkage is a separate measurement. Those percentages are not predictions for this plugin or for uncached input.

Local tests verify this helper's selected-evidence fidelity, byte budgets, source integrity, recovery and redaction behavior. Serialized byte changes are not provider-token, latency, cost or end-to-end quality measurements. The completed 0.3.18/0.3.19 comparison remains a mixed result, not proof of 0.3.20 savings. A future full comparison must count all recovery calls, required checks, worker/coordinator usage and final coverage.
