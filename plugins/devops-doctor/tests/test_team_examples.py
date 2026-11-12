import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import agent_handoff


class PackagedExamples(unittest.TestCase):
    def test_copied_example_does_not_cap_new_ready_work_at_two(self):
        assets = ROOT/'skills/devops-team/assets'
        plan = json.loads((assets/'team-plan.example.json').read_text(encoding='utf-8'))
        added = ['cache', 'queue', 'network', 'storage']
        for task_id in added:
            plan['tasks'].append({'id': task_id, 'role': 'investigator', 'read_keys': ['synthetic:' + task_id], 'write_paths': []})
        result = agent_handoff.combine(plan)
        self.assertEqual(set(result['ready_batches'][0]), {'runtime', 'logs', *added})
        self.assertEqual(result['ready_batches'][1], ['review'])

    def test_packaged_examples_follow_actual_contract(self):
        assets = ROOT/'skills/devops-team/assets'
        plan = json.loads((assets/'team-plan.example.json').read_text(encoding='utf-8'))
        reports = [json.loads((assets/name).read_text(encoding='utf-8')) for name in ('task-report.example.json','logs-report.example.json','review-report.example.json')]
        self.assertEqual(agent_handoff.combine(plan)['ready_batches'], [['runtime','logs'],['review']])
        self.assertEqual(agent_handoff.combine(plan,reports)['status'], 'complete')
        self.assertEqual(agent_handoff.combine(plan,reports[:1])['status'], 'partial')


if __name__ == '__main__':
    unittest.main()
