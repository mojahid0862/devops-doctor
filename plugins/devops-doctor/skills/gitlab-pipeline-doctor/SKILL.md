---
name: gitlab-pipeline-doctor
description: Investigate GitLab CI/CD pipeline failures, failed jobs, runner errors, job traces, artifacts, cache, Docker build failures, deploy gates, and GitLab pipeline or job URLs using glab-only read-only evidence. Use when the user gives a failed GitLab pipeline/job URL, red CI status, job log, runner failure, or asks why GitLab CI failed.
---

# GitLab Pipeline Doctor

## Rules

- Use `glab` only for GitLab remote actions: metadata, pipeline/job reads, traces, diffs, comments, and status checks.
- Do not use browser, curl, web search, or GitLab connectors for GitLab actions unless the user explicitly allows fallback.
- If `glab` is missing or auth fails, stop and report the exact blocker.
- Stay read-only unless the user explicitly approves retrying, canceling, triggering, approving, merging, or editing CI variables.
- Never print secrets, masked variables, tokens, deploy keys, registry credentials, or webhook secrets.
- Do not claim current pipeline/job state unless it comes from `glab` output, repo files, user-provided logs, or an explicit blocker.
- If evidence is missing, write `Unknown:` or `Blocked:` instead of guessing.

## Workflow

1. Parse the pipeline/job URL or user text for project path, pipeline ID, job ID, branch, commit SHA, and MR IID.
2. Verify `glab` and auth:

```bash
glab auth status
```

3. Capture bounded evidence with the helper when project path is known:

```bash
python ../../scripts/gitlab_pipeline_snapshot.py --repo <group/project> --pipeline-id <pipeline-id> --job-id <job-id> --output gitlab-pipeline-snapshot.json
```

4. Inspect local CI context when a checkout exists:

```bash
git status --short
find . -maxdepth 4 \( -name ".gitlab-ci.yml" -o -path "*/.gitlab/ci/*.yml" -o -name "Dockerfile*" -o -name "docker-compose*.yml" -o -name "package.json" -o -name "requirements*.txt" -o -name "pyproject.toml" -o -name "go.mod" \)
```

5. Classify the failure: CI syntax, rules, runner, dependency install, lint/test, build, Docker image, registry auth, cache/artifacts, permissions, Terraform plan, deploy, health check, rollback, or external dependency.
6. Compare the failing command to repo scripts, lockfiles, Dockerfile, and included CI files before proposing a fix.

## Output

```text
Root cause:
Failed job/stage:
Evidence:
Fix:
Validate:
Rollback:
Risk:
```

Keep the answer concise and include exact commands the user can rerun.
