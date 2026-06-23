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

## Workflow

1. Parse MR URL for `<group/project>` and MR IID.
2. Collect MR evidence:

```bash
glab auth status
python ../../scripts/gitlab_mr_snapshot.py --repo <group/project> --mr-iid <iid> --output gitlab-mr-snapshot.json
```

3. Inspect local checkout only when useful or already present:

```bash
git status --short
git branch --show-current
git remote -v
git diff --check <target>...<source>
```

4. Review changed code and config for:

- correctness and user-facing regressions
- `.gitlab-ci.yml` and included CI file behavior
- Docker image size, cache, secrets, root user, health checks
- AWS/IaC impact, IAM, SG/VPC, S3/RDS/ECS/Lambda safety
- deploy gates, branch rules, manual approvals, environments
- observability, rollback, tests, and migration risk

## Output

```text
Findings:
CI/CD:
Security:
Reliability:
Tests:
Fix:
Validate:
Risk:
```

If there are no findings, say that clearly and mention any remaining test or CI gaps.
