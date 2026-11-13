import io
import json
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

    def scan_repo(self, root, *options):
        stdout = io.StringIO()
        with patch.object(sys, 'argv', ['repo_devops_scan.py', '--root', str(root), *options]), \
             patch.object(sys, 'stdout', stdout):
            status = scan.main()
        return status, json.loads(stdout.getvalue())

    def test_package_metadata_uses_bounded_discovery(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'a.yaml').write_text('x', encoding='utf-8')
            (root / 'package.json').write_text('{"dependencies":{"react":"1"},"scripts":{"build":"vite"}}', encoding='utf-8')
            status, result = self.scan_repo(root)
            self.assertEqual(status, 0)
            self.assertIn('web', result['evidence']['app_type'])
            self.assertEqual(result['evidence']['package_scripts'], {'build': 'vite'})
            for option, value, skipped_large in (
                ('--max-file-bytes', '10', 1), ('--max-files', '1', 0),
            ):
                with self.subTest(option=option):
                    with patch.object(Path, 'open', autospec=True, side_effect=Path.open) as opened:
                        status, result = self.scan_repo(root, option, value)
                    self.assertEqual(status, 1)
                    self.assertTrue(result['coverage']['truncated'])
                    self.assertEqual(result['coverage']['skipped_large'], skipped_large)
                    self.assertEqual(result['evidence']['package_scripts'], {})
                    self.assertNotIn('web', result['evidence']['app_type'])
                    self.assertEqual([call.args[0].name for call in opened.call_args_list], ['a.yaml'])

    def test_package_symlink_is_skipped(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            package = root / 'package.json'
            package.write_text('{"dependencies":{"react":"1"}}', encoding='utf-8')
            # Model Windows installations where creating a symlink requires privileges.
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda path: path == package), \
                 patch.object(Path, 'open', side_effect=AssertionError('linked package must not be opened')):
                status, result = self.scan_repo(root)
            self.assertEqual(status, 1)
            self.assertEqual(result['coverage']['skipped_links'], 1)
            self.assertEqual(result['evidence']['app_type'], [])

    def test_invalid_package_metadata_is_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for metadata in ('["react"]', '{bad json', '{"dependencies":[]}', '{"scripts":null}',
                             '{"scripts":{"build":["vite"]}}', '{"devDependencies":{"vite":false}}'):
                with self.subTest(metadata=metadata):
                    (root / 'package.json').write_text(metadata, encoding='utf-8')
                    status, result = self.scan_repo(root)
                    self.assertEqual(status, 1)
                    self.assertEqual(result['status'], 'partial')
                    self.assertEqual(result['evidence']['package_scripts'], {})
                    self.assertIn('invalid_package_json', {finding['rule'] for finding in result['findings']})
                    self.assertEqual(result['blockers'][0]['scope'], 'package.json')

    def test_unreadable_package_metadata_is_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'package.json').write_text('{}', encoding='utf-8')
            with patch.object(Path, 'open', side_effect=PermissionError('access denied')):
                status, result = self.scan_repo(root)
            self.assertEqual(status, 1)
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['evidence']['package_scripts'], {})
            self.assertEqual(result['findings'][0]['rule'], 'read_error')
            self.assertEqual(result['blockers'][0]['scope'], 'package.json')

    @patch('aws_deploy_snapshot.aws_json', return_value={'ok': True, 'data': {}})
    def test_cross_account_ecr_uses_image_registry(self, call):
        deploy.collect_ecr_images({'ok': True, 'data': {'containerDefinitions': [{'name': 'app', 'image': '123456789012.dkr.ecr.ap-south-1.amazonaws.com/app:release'}]}}, None, 'us-east-1')
        command = call.call_args.args[0]
        self.assertEqual(command[command.index('--registry-id') + 1], '123456789012')
        self.assertEqual(call.call_args.args[2], 'ap-south-1')


if __name__ == '__main__':
    unittest.main()
