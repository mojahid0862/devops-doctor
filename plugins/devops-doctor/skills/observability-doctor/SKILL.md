---
name: observability-doctor
description: Diagnose incidents using logs, metrics, traces, alerts, SLOs, CloudWatch, Grafana, New Relic, ALB target health, CloudFront/Route 53 signals, ElastiCache/Redis health, ECS events, Kubernetes events, application logs, and deployment timelines. Use when the user gives an outage, alert, latency spike, error spike, noisy monitor, missing dashboard, or asks what to check in observability.
---

# Observability Doctor

Read [the shared evidence contract](../devops-doctor/references/evidence-contract.md). Resolve `<plugin-root>` from this skill's absolute path; preserve the user repository cwd.


## Rules

- Read-only first. Do not change alerts, dashboards, sampling, retention, or logging config without explicit approval.
- Correlate symptoms with deploys, infra events, and dependency status.
- Avoid dumping sensitive logs; redact secrets and user data.
- Do not claim incident state, alert status, metrics, or log facts unless it comes from telemetry output, repo config, user-provided evidence. A blocker means evidence is unavailable, not a verified system state.
- If evidence is missing, write `Unknown:` or `Blocked:` instead of guessing.

## Workflow

1. Establish incident window, service, region, user impact, SLO/SLA, and recent deploy.
2. Reuse fresh evidence and pull only missing signals. Choose the relevant connected-tool read or CLI example below, not all three; bind account/region and narrow alarm names, log groups, and service filters:

```bash
aws cloudwatch describe-alarms --region <region> --alarm-names <relevant-alarm-names>
aws logs tail <log-group> --region <region> --since <window>
python "<plugin-root>/scripts/aws_stack_snapshot.py" --region <region> --services <relevant-services> --since <window> --output observability-stack-snapshot.json
```

3. Prefer helper `summary`, `findings`, and `blockers`, then check:

- golden signals: latency, traffic, errors, saturation
- deploy markers and GitLab pipeline timing
- ALB 4xx/5xx, target response time, target health
- CloudFront 4xx/5xx, cache hit rate, origin latency, Route 53 health checks, DNS TTL/change timing
- ECS task restarts, OOM, CPU/memory, health check failures
- DB connections, CPU, locks, storage, failovers, Redis/ElastiCache failover, evictions, memory, or connection pressure
- missing alerts, noisy alerts, no runbook, no rollback signal

## Output

```text
Likely cause:
Evidence:
Queries/commands:
Fix:
Validate:
Alerting gap:
Risk:
```
