---
name: gitlab-mr-review
description: Review GitLab merge requests using glab-only read-only evidence for bugs, CI/CD risk, Docker/build risk, AWS deployment impact, security, reliability, tests, rollback, and production safety. Use when the user gives a GitLab MR URL, asks to review an MR, or wants CI/CD and AWS deployment risk checked before merge.
---

# GitLab MR Review

## Rules

- Use `glab` only for GitLab remote actions.
- Do not use browser, curl, web search, or GitLab connectors unless the user explicitly allows fallback.
- If `glab` is missing or unauthenticated, stop and report the exact blocker.
- Stay read-only. Do not approve, merge, comment, retry jobs, or push changes unless explicitly asked.
- Lead with findings ordered by severity. No filler.
- Do not claim MR, pipeline, approval, discussion, or diff state unless it comes from `glab` output, repo files, user-provided evidence, or an explicit blocker.
- If evidence is missing, write `Unknown:` or `Blocked:` instead of guessing.
- Default to a fast scored review. Target the first useful answer in under 90 seconds for normal MRs.
- Do not fetch discussions, raw file contents, job traces, or local checkout context unless a fast-pass finding needs proof, CI failed, the diff touches CI/Docker/IaC/security-sensitive code, the MR is very large, or the user asks for a deep review.
- If the user asks why a GitLab pipeline failed, gives a failed job/pipeline URL, asks for root cause, or asks for a deep GitLab investigation, route to `$gitlab-pipeline-doctor` or explicitly switch to heavy GitLab evidence mode. Do not run the heavy path for a normal MR score/review.

## Workflow

1. Parse MR URL for `<group/project>` and MR IID.
2. Fast-pass evidence, keeping GitLab remote calls small:

```bash
python ../../scripts/gitlab_mr_fast_review.py --repo <group/project> --mr-iid <iid> --output gitlab-mr-fast-review.json
glab auth status
glab mr view <iid> --repo <group/project> --output json
glab mr diff <iid> --repo <group/project>
```

3. Check CI status with one extra call when needed:

```bash
glab api projects/<url-encoded-project>/merge_requests/<iid>/pipelines
glab api projects/<url-encoded-project>/repository/commits/<sha>/statuses
```

Use commit statuses for the MR head SHA or merge commit SHA when the MR pipelines endpoint is empty. Do not enumerate all jobs unless a pipeline failed or the status is ambiguous.

Prefer the helper output's `summary.score`, `summary.verdict`, `evidence.risk_buckets`, and `findings` for the first answer. Only expand beyond it when blockers, failed CI, high-risk paths, or user intent require deeper proof.

4. Inspect local checkout only when useful or already present, and only after the fast pass shows a real need:

```bash
git status --short
git branch --show-current
git remote -v
git diff --check <target>...<source>
```

5. Review changed code and config for:

- correctness and user-facing regressions
- security: secrets, authz/authn, injection, unsafe redirects, sensitive logging, dependency or supply-chain risk
- performance: unnecessary network calls, expensive loops, cache busting, bundle/image bloat, query fan-out, memory leaks
- CI/CD: `.gitlab-ci.yml`, included CI files, Docker, deploy gates, branch rules, artifacts, cache, environments
- cloud/IaC when touched: AWS/Azure/GCP IAM, SG/VPC, S3/RDS/ECS/Lambda safety, Terraform/Helm/K8s blast radius
- deploy gates, branch rules, manual approvals, environments
- observability, rollback, tests, and migration risk

## Heavy GitLab Evidence Mode

Use this only when the user asks for failed-pipeline root cause, gives a failed pipeline/job URL, asks for "deep", "full", "why it failed", "trace logs", "discussions", or when the fast MR pass finds failed/ambiguous CI.

Heavy mode may collect:

- snapshot helper output
- MR discussions
- raw changed file context
- commit statuses
- pipeline jobs and failed job traces
- line-level source tracing

Keep heavy mode read-only and explain why it was triggered.

## Score

Start at 100 and subtract:

- Critical blocker: -50 each, cap score at 49.
- High severity bug/security/deploy risk: -30 each, cap score at 59.
- Medium correctness/security/performance/reliability issue: -15 each.
- Low cleanup or maintainability issue: -5 each.
- Failing required CI: -25, cap score at 59.
- Missing/unknown CI on an unmerged MR: -10.
- Missing obvious tests for touched risky behavior: -5 to -10.

Verdict:

- Score >= 60 and no critical/high blocker: `All good, can merge`.
- Score < 60 or any critical/high blocker: `Do not merge yet`, then list exact reasons and smallest fixes.
- If evidence is incomplete, give the score with `confidence: low/medium` and name the missing evidence.

## Output

```text
Score:
Verdict:
Changes:
Findings:
CI/CD:
Security:
Performance:
Reliability:
Tests:
Fix:
Validate:
Next:
```

If there are no findings, say that clearly and mention any remaining test or CI gaps.
