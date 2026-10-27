---
name: gitlab-mr-review
description: Review a GitLab MR using glab-only metadata, the actual diff, and current-commit CI evidence. Use for correctness, security, performance, delivery, or production-risk review before merge; route failed-job root-cause requests to gitlab-pipeline-doctor.
---

# GitLab MR Review

Read [the evidence contract](../devops-doctor/references/evidence-contract.md). GitLab remote actions use `glab` only. Stop with the exact blocker if it is missing or unauthenticated. Do not approve, merge, post, retry, or push without authorization.

## Fast path

1. Resolve project, host, and MR IID. Keep metadata/diff/CI tied to the same current head SHA and matching base/start diff refs. For a self-managed host, use the user's existing `glab` host configuration and verify the target.
2. Choose the helper OR equivalent direct calls, not both:

```bash
python "<plugin-root>/scripts/gitlab_mr_fast_review.py" --repo <group/project> --mr-iid <iid> --output <work-dir>/mr-review.json
```

For equivalent direct reads, use `glab auth status` and `glab api` to collect MR metadata and its latest collected diff version. Fetch that version by ID, verify matching head/base/start refs, query current-SHA CI, then reread MR refs once to detect drift. A mutable `glab mr diff` read alone does not establish revision provenance. Missing refs, omitted content, or changed revisions leave the review incomplete. The helper bounds pagination and runs independent reads concurrently.

3. Review the actual changed code, including context needed to prove a finding. The helper's pattern findings are triage hints, not a code review. Missing/clipped diff means incomplete review.
4. Expand to raw file context, discussions, checkout, traces, or tests only when a finding needs proof, CI failed, high-risk changes need deeper validation, or the user requests a deep review.

## Verdict

- A risk score is optional unless requested; it is never the merge gate.
- Unknown, missing, running, pending, or skipped CI is unverified. A successful older pipeline, merge commit, or another SHA is not current-head proof.
- Missing auth, fetch errors, truncation, pagination caps, or missing required gates produce `Review incomplete` and the specific gap.
- Critical/high blockers or failed required checks produce `Do not merge yet` with exact reasons.
- Complete helper evidence produces `Evidence checks passed; review required`. The agent may conclude `No blocking findings in reviewed scope` after actual review, stating remaining limitations and required approvals. Do not automatically declare an MR safe to merge from a numeric score.

Lead with actionable findings, severity, file/line evidence, impact, and the smallest fix. State CI status and SHA, tests actually run, and gaps. If no findings, say so without implying unperformed checks passed.
