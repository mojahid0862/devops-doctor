import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import repo_devops_scan as scan
import aws_deploy_snapshot as deploy


class LocalHelperTests(unittest.TestCase):
    def test_scan_prunes_dependencies_and_reports_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'node_modules' / 'nested').mkdir(parents=True)
            (root / 'node_modules' / 'nested' / 'unsafe.tf').write_text('x')
            (root / 'a.tf').write_text('x')
            (root / 'b.tf').write_text('x' * 30)
            files, coverage = scan.discover_files(root, 10, 10)
            self.assertEqual([p.name for p in files], ['a.tf'])
            self.assertEqual(coverage['skipped_large'], 1)
            self.assertTrue(coverage['truncated'])
            files, coverage = scan.discover_files(root, 1, 100)
            self.assertEqual(len(files), 1)
            self.assertTrue(coverage['truncated'])

    @patch('aws_deploy_snapshot.aws_json', return_value={'ok': True, 'data': {}})
    def test_cross_account_ecr_uses_image_registry(self, call):
        deploy.collect_ecr_images({'ok': True, 'data': {'containerDefinitions': [{'name': 'app', 'image': '123456789012.dkr.ecr.ap-south-1.amazonaws.com/app:release'}]}}, None, 'us-east-1')
        command = call.call_args.args[0]
        self.assertEqual(command[command.index('--registry-id') + 1], '123456789012')
        self.assertEqual(call.call_args.args[2], 'ap-south-1')


if __name__ == '__main__':
    unittest.main()
