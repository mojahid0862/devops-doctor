"""Offline package validation. Does not contact cloud/GitLab or execute collectors."""
import ast
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    portable = json.loads((ROOT / 'plugin.json').read_text(encoding='utf-8'))
    compat = json.loads((ROOT / '.codex-plugin/plugin.json').read_text(encoding='utf-8'))
    for key in ('name', 'version', 'author', 'description'):
        assert portable[key] == compat[key], f'Manifest mismatch: {key}'
    assert portable['extensions']['com.openai']['interface'] == compat['interface'], 'Interface mismatch'
    assert (ROOT / compat['skills']).is_dir()
    for field in ('composerIcon', 'logo'):
        asset = (ROOT / compat['interface'][field]).resolve()
        assert asset.is_relative_to(ROOT) and asset.is_file(), f'Invalid asset: {field}'
    skills = list((ROOT / 'skills').glob('*/SKILL.md'))
    for path in skills:
        text = path.read_text(encoding='utf-8')
        assert text.startswith('---\n'), f'Frontmatter missing: {path}'
        header = text.split('---', 2)[1]
        assert re.search(r'^name:\s*' + re.escape(path.parent.name) + r'\s*$', header, re.M), path
        assert re.search(r'^description:\s*\S', header, re.M), path
        for relative in re.findall(r'\]\(([^)]+\.md)\)', text):
            target = (path.parent / relative).resolve()
            assert target.is_relative_to(ROOT) and target.is_file(), f'Broken reference: {relative}'
    helpers = list((ROOT / 'scripts').glob('*.py'))
    for path in helpers:
        ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        if path.name == 'doctor_common.py':
            continue
        result = subprocess.run([sys.executable, '-B', str(path), '--help'], capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, f'CLI help failed: {path.name}: {result.stderr}'
    completed = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-q'], cwd=ROOT)
    if completed.returncode:
        return completed.returncode
    print(json.dumps({'version': portable['version'], 'skills': len(skills), 'python_modules': len(helpers), 'cli_smoke_checks': len(helpers)-1, 'validation': 'passed', 'live_cloud_gitlab_calls': 0}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
