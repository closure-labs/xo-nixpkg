# SPDX-License-Identifier: Apache-2.0
"""Installer transport/integrity failures never expose a usable scanner output."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / '.github/actions/setup-gitleaks/action.yml'


class GitleaksSetup(unittest.TestCase):
    def invoke(self, **changes):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mock = root / 'bin'; mock.mkdir()
            for name, source in {
                'curl': 'import os,sys\nfrom pathlib import Path\na=sys.argv;Path(a[a.index("-o")+1]).write_bytes(b"synthetic archive")\nsys.exit(int(os.environ.get("CURL_STATUS","0")))\n',
                'sha256sum': 'import os,sys\nsys.stdin.read()\nsys.exit(int(os.environ.get("HASH_STATUS","0")))\n',
                'tar': ('import sys\nfrom pathlib import Path\na=sys.argv;d=Path(a[a.index("-C")+1]);p=d/"gitleaks"\np.write_text(' + repr('#!' + sys.executable + '\nimport os\nfrom pathlib import Path\nPath(os.environ["VERSION_MARKER"]).write_text("called")\nprint(os.environ.get("MOCK_VERSION", "8.30.1"))\n') + ')\np.chmod(0o755)\n'),
            }.items():
                executable = mock / name
                executable.write_text('#!' + sys.executable + '\n' + source)
                executable.chmod(0o755)
            output = root / 'outputs'; marker = root / 'version-called'
            env = dict(os.environ, RUNNER_TEMP=str(root), GITHUB_OUTPUT=str(output),
                       VERSION_MARKER=str(marker), PATH=str(mock) + os.pathsep + os.environ['PATH'])
            env.update(changes)
            script = yaml.safe_load(ACTION.read_text())['runs']['steps'][0]['run']
            result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, timeout=5)
            return result.returncode, output.read_text() if output.exists() else '', marker.exists()

    def test_integrity_and_version_must_pass_before_output(self):
        code, output, called = self.invoke()
        self.assertEqual(code, 0)
        self.assertTrue(output.startswith('binary='))
        self.assertTrue(called)
        for env in ({'CURL_STATUS': '22'}, {'HASH_STATUS': '1'}, {'MOCK_VERSION': 'different'}):
            code, output, called = self.invoke(**env)
            self.assertNotEqual(code, 0)
            self.assertEqual(output, '')
            if 'MOCK_VERSION' not in env:
                self.assertFalse(called)

    def test_shared_pin_and_no_path_mutation(self):
        source = ACTION.read_text()
        self.assertIn('551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb', source)
        self.assertIn('--max-time 60', source)
        self.assertNotIn('GITHUB_PATH', source)
        self.assertNotIn('inputs:', source)
        self.assertEqual(source.count('releases/download/'), 1)

    def test_authoritative_policy_is_separate_from_proposed_fixture_action(self):
        required = (ROOT / '.github/workflows/repository-secret-scan.yml').read_text()
        self.assertNotIn('setup-gitleaks', required)
        self.assertIn('sparse-checkout: .gitleaks.toml', required)
        self.assertIn('--config "$GITHUB_WORKSPACE/controller/.gitleaks.toml"', required)
        for filename in ('gitleaks-policy-fixtures.yml', 'diagnostic-secret-triage.yml'):
            source = (ROOT / '.github/workflows' / filename).read_text()
            self.assertIn('uses: $/.github/actions/setup-gitleaks', source)
            self.assertIn('GITLEAKS_BINARY: ${{ steps.gitleaks.outputs.binary }}', source)
            self.assertNotIn('releases/download/', source)
            self.assertNotIn('secrets.', source)


if __name__ == '__main__':
    unittest.main()
