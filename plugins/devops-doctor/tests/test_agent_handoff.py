import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import agent_handoff as handoff


def plan():
    return {'schema_version': '1.0', 'run_id': 'incident-001', 'scope': {'account_id': '123456789012', 'region': 'ap-south-1', 'window': '2026-10-26T10:00:00Z/2026-10-26T11:00:00Z'}, 'max_workers': 2,
            'tasks': [{'id': 'ecs', 'role': 'investigator', 'read_keys': ['ecs:cluster/app']}, {'id': 'logs', 'role': 'investigator', 'read_keys': ['logs:app']}, {'id': 'review', 'role': 'reviewer', 'depends_on': ['ecs', 'logs'], 'review_of': ['ecs', 'logs']}]}


def report(task_id='ecs', **changes):
    result = {'run_id': 'incident-001', 'task_id': task_id, 'status': 'complete', 'scope': copy.deepcopy(plan()['scope']), 'summary': 'Inspected the selected evidence.',
              'evidence': [{'id': 'e1', 'source': 'work/sanitized-snapshot.json', 'observed_at': '2026-10-26T11:00:00+00:00', 'claim': 'Observation in supplied scope.'}],
              'findings': [], 'changed_files': [], 'tests': [], 'blockers': [], 'reviewed_tasks': ['ecs', 'logs'] if task_id == 'review' else []}
    result.update(changes)
    return result


class PlanTests(unittest.TestCase):
    def test_dependency_batches_obey_worker_bound(self):
        data = plan()
        result = handoff.combine(data)
        self.assertEqual(result['ready_batches'], [['ecs', 'logs'], ['review']])
        data['max_workers'] = 1
        self.assertEqual(handoff.combine(data)['ready_batches'], [['ecs'], ['logs'], ['review']])
        self.assertEqual(result['mode'], 'plan')

    def test_cycles_and_unknown_dependencies_rejected(self):
        for depends in (['missing'], ['review']):
            data = plan()
            data['tasks'][0]['depends_on'] = depends
            with self.subTest(depends=depends), self.assertRaises(ValueError):
                handoff.combine(data)

    def test_review_targets_must_be_dependencies(self):
        data = plan()
        data['tasks'][-1]['depends_on'] = ['ecs']
        with self.assertRaises(ValueError):
            handoff.combine(data)

    def test_duplicate_task_and_read_ownership_rejected(self):
        for field, value in (('id', 'ecs'), ('read_keys', ['ecs:cluster/app'])):
            data = plan()
            data['tasks'][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                handoff.combine(data)

    def test_file_ownership_rejects_parent_and_case_overlap(self):
        for first, second in (('src', 'src/app.py'), ('src/App.py', 'SRC/app.py'), ('src/app.py', 'src')):
            data = plan()
            data['tasks'][0]['write_paths'] = [first]
            data['tasks'][1]['write_paths'] = [second]
            with self.subTest(first=first, second=second), self.assertRaises(ValueError):
                handoff.combine(data)

    def test_invalid_paths_and_invalid_concurrency(self):
        for value in ('../outside', '/root/file', 'C:/project/file', 'C:relative', 'src/*.py', '.', 'src/file:stream', 'src/unsafe.'):
            with self.subTest(path=value), self.assertRaises(ValueError):
                handoff.path_parts(value)
        for value in (True, False, 0, -1, '2', 'AUTO', '', None, 2.0, [], {}):
            data = plan()
            data['max_workers'] = value
            with self.subTest(workers=value), self.assertRaises(ValueError):
                handoff.combine(data)

    def test_requested_eight_and_twelve_workers_are_preserved(self):
        for workers in (8, 12):
            data = plan()
            data['max_workers'] = workers
            data['tasks'] = [{'id': f'probe-{index}', 'role': 'investigator'} for index in range(12)]
            with self.subTest(workers=workers):
                result = handoff.combine(data)
                self.assertEqual(len(result['ready_batches'][0]), workers)
                self.assertEqual(sum(map(len, result['ready_batches'])), 12)
                self.assertEqual(result['concurrency'], {'requested': workers, 'runtime_capacity': None, 'effective_plan_workers': workers, 'worker_limit': 20})

    def test_auto_default_and_explicit_auto_follow_task_count(self):
        for explicit in (False, True):
            data = plan()
            data.pop('max_workers')
            if explicit:
                data['max_workers'] = 'auto'
            data['tasks'] = [{'id': f'probe-{index}', 'role': 'investigator'} for index in range(9)]
            with self.subTest(explicit=explicit):
                result = handoff.combine(data)
                self.assertEqual(len(result['ready_batches']), 1)
                self.assertEqual(len(result['ready_batches'][0]), 9)
                self.assertEqual(result['concurrency'], {'requested': 'auto', 'runtime_capacity': None, 'effective_plan_workers': 9, 'worker_limit': 20})

    def test_auto_and_explicit_twenty_share_a_twenty_worker_limit(self):
        for requested in (None, 'auto', 20):
            for capacity in (None, 40):
                data = plan()
                data.pop('max_workers')
                if requested is not None:
                    data['max_workers'] = requested
                if capacity is not None:
                    data['runtime_capacity'] = capacity
                data['tasks'] = [{'id': f'probe-{index}', 'role': 'investigator'} for index in range(25)]
                with self.subTest(requested=requested, capacity=capacity):
                    result = handoff.combine(data)
                    self.assertEqual(result['ready_batches'], [[f'probe-{index}' for index in range(20)], [f'probe-{index}' for index in range(20, 25)]])
                    self.assertEqual(result['concurrency'], {'requested': requested if requested is not None else 'auto', 'runtime_capacity': capacity, 'effective_plan_workers': 20, 'worker_limit': 20})
                    self.assertTrue(any('all subagents and descendants' in item for item in result['limitations']))

    def test_more_than_twenty_requested_workers_are_rejected_clearly(self):
        for requested in (21, 100):
            data = plan()
            data.update(max_workers=requested, runtime_capacity=3)
            with self.subTest(requested=requested), self.assertRaisesRegex(ValueError, 'integer from 1 to 20'):
                handoff.combine(data)

    def test_auto_with_two_tasks_uses_two_workers(self):
        data = plan()
        data.pop('max_workers')
        data['tasks'] = data['tasks'][:2]
        result = handoff.combine(data)
        self.assertEqual(result['ready_batches'], [['ecs', 'logs']])
        self.assertEqual(result['concurrency']['effective_plan_workers'], 2)

    def test_caller_runtime_capacity_clamps_auto_and_explicit_requests(self):
        for requested in ('auto', 8, 12, 20):
            data = plan()
            data.update(max_workers=requested, runtime_capacity=3)
            data['tasks'] = [{'id': f'probe-{index}', 'role': 'investigator'} for index in range(8)]
            with self.subTest(requested=requested):
                result = handoff.combine(data)
                self.assertEqual([len(batch) for batch in result['ready_batches']], [3, 3, 2])
                self.assertEqual(result['concurrency']['effective_plan_workers'], 3)
                self.assertEqual(result['concurrency']['runtime_capacity'], 3)
                self.assertTrue(any('caller-supplied' in item for item in result['limitations']))

    def test_small_task_count_caps_capacity_without_ignoring_dependencies(self):
        data = plan()
        data.update(max_workers=12, runtime_capacity=20)
        result = handoff.combine(data)
        self.assertEqual(result['concurrency']['effective_plan_workers'], 3)
        self.assertEqual(result['ready_batches'], [['ecs', 'logs'], ['review']])
        data.update(max_workers=1, runtime_capacity=20)
        self.assertEqual(handoff.combine(data)['concurrency']['effective_plan_workers'], 1)

    def test_invalid_runtime_capacity_is_rejected(self):
        for value in (True, False, 0, -1, '3', 'auto', None, 3.0, [], {}):
            data = plan()
            data['runtime_capacity'] = value
            with self.subTest(runtime_capacity=value), self.assertRaises(ValueError):
                handoff.combine(data)


class ReportTests(unittest.TestCase):
    def test_complete_team_is_schema_checked_only(self):
        result = handoff.combine(plan(), [report('ecs'), report('logs'), report('review')])
        self.assertEqual(result['status'], 'complete')
        self.assertFalse(result['blockers'])
        self.assertTrue(any('truth' in item for item in result['limitations']))

    def test_missing_required_report_is_partial(self):
        result = handoff.combine(plan(), [report('ecs')])
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['missing_tasks'], ['logs', 'review'])

    def test_optional_absence_does_not_fail(self):
        data = plan()
        data['tasks'][1]['required'] = False
        data['tasks'] = data['tasks'][:2]
        self.assertEqual(handoff.combine(data, [report()])['status'], 'complete')

    def test_failed_and_blocked_reports_are_visible(self):
        for status, expected in (('failed', 'failed'), ('blocked', 'partial'), ('partial', 'partial')):
            reports = [report('ecs', status=status), report('logs'), report('review')]
            with self.subTest(status=status):
                self.assertEqual(handoff.combine(plan(), reports)['status'], expected)

    def test_complete_with_blockers_or_empty_evidence_is_partial(self):
        for changes in ({'blockers': ['AccessDenied']}, {'evidence': []}, {'tests': [{'command': 'python -m unittest', 'status': 'failed'}]}):
            reports = [report('ecs', **changes), report('logs'), report('review')]
            with self.subTest(changes=changes):
                self.assertEqual(handoff.combine(plan(), reports)['status'], 'partial')

    def test_scope_run_and_duplicate_report_mismatch(self):
        for changes in ({'scope': {'region': 'other'}}, {'run_id': 'another-run'}, {'task_id': 'unknown'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                handoff.combine(plan(), [report(**changes)])
        with self.assertRaises(ValueError):
            handoff.combine(plan(), [report(), report()])

    def test_evidence_refs_and_aware_timestamps_required(self):
        finding = {'id': 'f1', 'severity': 'high', 'summary': 'Service mismatch.', 'confidence': 'high', 'evidence_ids': ['missing']}
        with self.assertRaises(ValueError):
            handoff.combine(plan(), [report(findings=[finding])])
        data = report()
        data['evidence'][0]['observed_at'] = '2026-10-26T11:00:00'
        with self.assertRaises(ValueError):
            handoff.combine(plan(), [data])
        finding['evidence_ids'] = ['e1']
        self.assertEqual(len(handoff.combine(plan(), [report(findings=[finding])])['findings']), 1)

    def test_changed_paths_must_belong_to_task(self):
        data = plan()
        data['tasks'][0]['write_paths'] = ['src/service']
        self.assertEqual(handoff.combine(data, [report(changed_files=['src/service/main.py'])])['status'], 'partial')
        with self.assertRaises(ValueError):
            handoff.combine(data, [report(changed_files=['src/other.py'])])

    def test_incomplete_review_does_not_count_as_complete(self):
        reports = [report('ecs'), report('logs'), report('review', reviewed_tasks=['ecs'])]
        self.assertEqual(handoff.combine(plan(), reports)['status'], 'partial')

    def test_conflicting_fact_values_same_scope_require_resolution(self):
        reports = [report('ecs'), report('logs'), report('review')]
        for item, value in zip(reports[:2], (2, 0)):
            item['evidence'][0].update(fact_key='service.running_count', value=value)
        result = handoff.combine(plan(), reports)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['conflicts']), 1)
        self.assertEqual(result['conflicts'][0]['fact_key'], 'service.running_count')

    def test_different_scopes_do_not_create_false_conflict(self):
        data = plan()
        override = {'account_id': 'other', 'region': 'ap-south-1'}
        data['tasks'][1]['scope'] = override
        reports = [report('ecs'), report('logs', scope=override), report('review')]
        for item, value in zip(reports[:2], (2, 0)):
            item['evidence'][0].update(fact_key='service.running_count', value=value)
        self.assertFalse(handoff.combine(data, reports)['conflicts'])

    def test_secret_fact_values_are_hidden_in_reports_and_conflicts(self):
        reports = [report('ecs'), report('logs'), report('review')]
        for item, value in zip(reports[:2], ('sensitive-value-one', 'sensitive-value-two')):
            item['evidence'][0].update(fact_key='service.api_token', value=value)
        result = handoff.combine(plan(), reports)
        self.assertEqual(len(result['conflicts']), 1)
        self.assertNotIn('sensitive-value', json.dumps(result))

    def test_cli_sanitizes_and_does_not_execute_commands(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            plan_path, report_path, output = folder / 'plan.json', folder / 'report.json', folder / 'result.json'
            plan_path.write_text(json.dumps(plan()))
            report_path.write_text(json.dumps(report(summary='password=synthetic-private-value', tests=[{'command': 'DO-NOT-EXECUTE --token synthetic-token-value', 'status': 'not_run'}])))
            with patch.object(sys, 'argv', ['agent_handoff.py', '--plan', str(plan_path), '--reports', str(report_path), '--output', str(output)]), patch('subprocess.run', side_effect=AssertionError('must not execute')):
                self.assertEqual(handoff.main(), 1)
            self.assertNotIn('synthetic-private-value', output.read_text())
            self.assertNotIn('synthetic-token-value', output.read_text())

    def test_cli_invalid_input_returns_structured_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            bad = Path(folder) / 'bad.json'
            bad.write_text('{malformed')
            with patch.object(sys, 'argv', ['agent_handoff.py', '--plan', str(bad)]), redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(handoff.main(), 2)
            self.assertEqual(json.loads(stream.getvalue())['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
