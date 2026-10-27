"""Offline validation of team plans/reports; never executes or spawns anything."""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from doctor_common import MASK, emit_result, sanitize, secret_key

WORKER_LIMIT = 20

LIMITATIONS = [
    "Schema and consistency checks do not verify report truth, authorization, or production safety.",
    "Batches and effective_plan_workers are a proposed dependency order and ceiling, not evidence that agents ran or that host capacity was verified.",
    "runtime_capacity, when provided, is a caller-supplied positive worker count excluding the coordinator; this offline tool does not discover or verify it.",
    "The 20-worker limit is shared by all subagents and descendants for one main coordinator; it is not a separate allowance per worker.",
    "Path ownership is lexical; the coordinator must enforce workspace boundaries and resolve symlinks before edits.",
    "Conflicts compare explicit fact_key/value pairs within exactly matching scopes; other contradictions require human/agent review.",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def text(value: Any, field: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{field} must be a nonempty string")
    return value


def strings(value: Any, field: str) -> list[str]:
    require(isinstance(value, list), f"{field} must be a list")
    for item in value:
        text(item, field)
    require(len(set(value)) == len(value), f"{field} contains duplicates")
    return value


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def scope(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict) and bool(value), "scope must be a nonempty object")
    canonical(value)
    return value


def path_parts(value: Any) -> tuple[str, ...]:
    value = text(value, "write/changed path").replace("\\", "/")
    require(not any(char in value for char in '*?[]:\x00\r\n'), "paths must be concrete relative paths, without glob/drive/control characters")
    parsed = PurePosixPath(value)
    require(not parsed.is_absolute() and not PureWindowsPath(value).drive and '..' not in parsed.parts and bool(parsed.parts), "paths must stay inside the repository and cannot name its root")
    require(all(part not in {'.', '..'} and not part.endswith((' ', '.')) for part in parsed.parts), "ambiguous path component")
    return tuple(part.casefold() for part in parsed.parts)


def under(child: tuple[str, ...], parent: tuple[str, ...]) -> bool:
    return child[:len(parent)] == parent


def safe_result(value: Any) -> Any:
    if isinstance(value, list):
        return [safe_result(item) for item in value]
    if isinstance(value, dict):
        result = {key: safe_result(item) for key, item in value.items()}
        if isinstance(value.get('fact_key'), str) and secret_key(value['fact_key']):
            if 'value' in result:
                result['value'] = MASK
            for item in result.get('evidence', []):
                if isinstance(item, dict) and 'value' in item:
                    item['value'] = MASK
        return sanitize(result)
    return sanitize(value)


def concurrency(plan: dict[str, Any], task_count: int) -> dict[str, Any]:
    requested = plan.get('max_workers', 'auto')
    require(requested == 'auto' or (type(requested) is int and 1 <= requested <= WORKER_LIMIT), "max_workers must be 'auto' or an integer from 1 to 20 (shared across all subagents and descendants, excluding the main coordinator)")
    capacity = plan.get('runtime_capacity')
    require('runtime_capacity' not in plan or (type(capacity) is int and capacity > 0), "runtime_capacity must be a positive integer excluding the coordinator")
    effective = min(task_count, WORKER_LIMIT, requested if type(requested) is int else task_count, capacity if capacity is not None else task_count)
    return {'requested': requested, 'runtime_capacity': capacity, 'effective_plan_workers': effective, 'worker_limit': WORKER_LIMIT}


def validate_plan(plan: Any) -> tuple[dict[str, dict[str, Any]], list[list[str]]]:
    require(isinstance(plan, dict), "plan must be an object")
    require(plan.get('schema_version') == '1.0', "plan schema_version must be 1.0")
    text(plan.get('run_id'), 'run_id')
    scope(plan.get('scope'))
    rows = plan.get('tasks')
    require(isinstance(rows, list) and bool(rows), "tasks must be a nonempty list")
    workers = concurrency(plan, len(rows))['effective_plan_workers']
    tasks: dict[str, dict[str, Any]] = {}
    owners: list[tuple[str, tuple[str, ...]]] = []
    read_owners: dict[str, str] = {}
    for row in rows:
        require(isinstance(row, dict), "each task must be an object")
        task_id = text(row.get('id'), 'task id')
        require(task_id not in tasks, f"duplicate task id: {task_id}")
        text(row.get('role'), 'role')
        require(type(row.get('required', True)) is bool, "required must be boolean")
        scope(row.get('scope', plan['scope']))
        for key in ('depends_on', 'write_paths', 'read_keys', 'review_of'):
            strings(row.get(key, []), key)
        require(task_id not in row.get('depends_on', []), "task cannot depend on itself")
        for path in row.get('write_paths', []):
            parts = path_parts(path)
            for owner, owned in owners:
                require(owner == task_id or not (under(parts, owned) or under(owned, parts)), f"overlapping write ownership: {owner}, {task_id}")
            owners.append((task_id, parts))
        for key in row.get('read_keys', []):
            require(key not in read_owners, f"duplicate read ownership: {key}")
            read_owners[key] = task_id
        tasks[task_id] = row
    for task_id, row in tasks.items():
        dependencies = set(row.get('depends_on', []))
        require(dependencies <= tasks.keys(), f"unknown dependency for {task_id}")
        require(set(row.get('review_of', [])) <= dependencies, f"review_of must be dependencies for {task_id}")
    pending, done, batches = list(tasks), set(), []
    while pending:
        batch = [key for key in pending if set(tasks[key].get('depends_on', [])) <= done][:workers]
        require(bool(batch), "dependency cycle")
        batches.append(batch)
        done.update(batch)
        pending = [key for key in pending if key not in done]
    return tasks, batches


def validate_report(report: Any, plan: dict[str, Any], tasks: dict[str, dict[str, Any]]) -> dict[str, Any]:
    require(isinstance(report, dict), "report must be an object")
    require(report.get('run_id') == plan['run_id'], "report run_id mismatch")
    task_id = text(report.get('task_id'), 'task_id')
    require(task_id in tasks, "report has unknown task_id")
    task = tasks[task_id]
    require(report.get('status') in {'complete', 'partial', 'blocked', 'failed'}, "invalid report status")
    require(canonical(scope(report.get('scope'))) == canonical(task.get('scope', plan['scope'])), f"report scope mismatch for {task_id}")
    text(report.get('summary'), 'summary')
    for key in ('evidence', 'findings', 'changed_files', 'tests', 'blockers', 'reviewed_tasks'):
        require(isinstance(report.get(key), list), f"report {key} must be a list")
    strings(report['blockers'], 'blockers')
    reviewed = strings(report['reviewed_tasks'], 'reviewed_tasks')
    require(set(reviewed) <= set(task.get('review_of', [])), "reviewed_tasks contains unassigned review targets")
    evidence_ids = set()
    for entry in report['evidence']:
        require(isinstance(entry, dict), "evidence entry must be an object")
        identifier = text(entry.get('id'), 'evidence id')
        require(identifier not in evidence_ids, "duplicate evidence id")
        evidence_ids.add(identifier)
        text(entry.get('source'), 'evidence source')
        text(entry.get('claim'), 'evidence claim')
        stamp = datetime.fromisoformat(text(entry.get('observed_at'), 'observed_at').replace('Z', '+00:00'))
        require(stamp.utcoffset() is not None, "observed_at must include a timezone")
        if 'fact_key' in entry:
            text(entry['fact_key'], 'fact_key')
            require('value' in entry, "fact_key requires value")
            canonical(entry['value'])
    finding_ids = set()
    for finding in report['findings']:
        require(isinstance(finding, dict), "finding must be an object")
        identifier = text(finding.get('id'), 'finding id')
        require(identifier not in finding_ids, "duplicate finding id")
        finding_ids.add(identifier)
        text(finding.get('summary'), 'finding summary')
        require(finding.get('severity') in {'critical', 'high', 'medium', 'low', 'info'}, "invalid finding severity")
        require(finding.get('confidence') in {'high', 'medium', 'low'}, "invalid finding confidence")
        refs = strings(finding.get('evidence_ids'), 'evidence_ids')
        require(bool(refs) and set(refs) <= evidence_ids, "finding requires existing evidence references")
    owned = [path_parts(path) for path in task.get('write_paths', [])]
    for path in strings(report['changed_files'], 'changed_files'):
        parts = path_parts(path)
        require(any(under(parts, parent) for parent in owned), f"changed file outside task ownership: {path}")
    for test in report['tests']:
        require(isinstance(test, dict), "test must be an object")
        text(test.get('command'), 'test command')
        require(test.get('status') in {'passed', 'failed', 'not_run'}, "invalid test status")
    return report


def combine(plan: dict[str, Any], reports: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    tasks, batches = validate_plan(plan)
    result: dict[str, Any] = {'status': 'complete', 'run_id': plan['run_id'], 'scope': plan['scope'], 'mode': 'plan' if reports is None else 'reports', 'plan_valid': True, 'concurrency': concurrency(plan, len(tasks)), 'ready_batches': batches, 'blockers': [], 'conflicts': [], 'findings': [], 'limitations': LIMITATIONS}
    if reports is None:
        return safe_result(result)
    received = {}
    for report in reports:
        validated = validate_report(report, plan, tasks)
        task_id = validated['task_id']
        require(task_id not in received, f"duplicate task report: {task_id}")
        received[task_id] = validated
    missing = [key for key, task in tasks.items() if task.get('required', True) and key not in received]
    result['missing_tasks'] = missing
    for task_id in missing:
        result['blockers'].append({'task_id': task_id, 'reason': 'required report missing'})
    facts: dict[tuple[str, str], list[dict[str, Any]]] = {}
    normalized = []
    for task_id, report in received.items():
        reasons = list(report['blockers'])
        if report['status'] != 'complete':
            reasons.append('reported status: ' + report['status'])
        missing_reviews = set(tasks[task_id].get('review_of', [])) - set(report['reviewed_tasks'])
        if missing_reviews:
            reasons.append('assigned reviews missing: ' + ', '.join(sorted(missing_reviews)))
        if report['status'] == 'complete' and not report['evidence']:
            reasons.append('complete report has no evidence')
        for dependency in tasks[task_id].get('depends_on', []):
            prior = received.get(dependency)
            if not prior or prior['status'] != 'complete' or prior['blockers'] or not prior['evidence']:
                reasons.append('dependency incomplete: ' + dependency)
        if any(test['status'] == 'failed' for test in report['tests']):
            reasons.append('reported test failure')
        for reason in dict.fromkeys(reasons):
            result['blockers'].append({'task_id': task_id, 'reason': reason})
        if report['status'] == 'failed':
            result['status'] = 'failed'
        normalized.append({'task_id': task_id, 'reported_status': report['status'], 'summary': report['summary'], 'evidence': report['evidence'], 'changed_files': report['changed_files'], 'tests': report['tests'], 'reviewed_tasks': report['reviewed_tasks']})
        result['findings'].extend({**finding, 'task_id': task_id} for finding in report['findings'])
        for entry in report['evidence']:
            if 'fact_key' in entry:
                key = (canonical(report['scope']), entry['fact_key'])
                facts.setdefault(key, []).append({'task_id': task_id, 'evidence_id': entry['id'], 'value': entry['value']})
    for (fact_scope, fact_key), entries in facts.items():
        if len({canonical(entry['value']) for entry in entries}) > 1:
            result['conflicts'].append({'scope': json.loads(fact_scope), 'fact_key': fact_key, 'evidence': entries})
    result['reports'] = normalized
    result['summary'] = {'required_tasks': sum(task.get('required', True) for task in tasks.values()), 'reports_received': len(received), 'missing_required': len(missing), 'conflicts': len(result['conflicts'])}
    if result['status'] != 'failed' and (result['blockers'] or result['conflicts']):
        result['status'] = 'partial'
    return safe_result(result)


def load(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding='utf-8-sig'), parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite JSON value')))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, help='JSON team plan; without reports validate and propose bounded batches.')
    parser.add_argument('--reports', nargs='+', help='Saved task reports; commands and evidence sources are never executed.')
    parser.add_argument('--output', help='Write sanitized combined result.')
    args = parser.parse_args()
    try:
        result = combine(load(args.plan), [load(path) for path in args.reports] if args.reports else None)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        result = {'status': 'failed', 'plan_valid': False, 'blockers': [{'scope': 'agent_handoff', 'reason': str(exc)}], 'limitations': LIMITATIONS}
    return emit_result(sanitize(result), args.output)


if __name__ == '__main__':
    raise SystemExit(main())
