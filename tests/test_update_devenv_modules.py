# SPDX-License-Identifier: Apache-2.0
"""The existing updater must retain native-only changes and reject split inputs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class UpdateLocksTests(unittest.TestCase):
    def run_update(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = {'root': 'root', 'nodes': {'root': {'inputs': {'nixpkgs': 'pkgs', 'devenv': 'devenv'}}, 'devenv': {'locked': {'rev': 'old'}},
                                'pkgs': {'locked': {'type': 'github', 'rev': 'same', 'narHash': 'hash'}}}}
            for name in ('flake.lock', 'devenv.lock'):
                (root / name).write_text(json.dumps(source))
            binary = root / 'nix'
            binary.write_text('#!' + sys.executable + '\n' + '''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with Path('calls').open('a') as stream: stream.write(json.dumps(args) + '\\n')
if args == ['run', '--accept-flake-config', '.#devenv', '--', 'update', 'devenv']:
    value = json.loads(Path('devenv.lock').read_text())
    if os.environ['UPDATE_MODE'] == 'split': value['nodes']['pkgs']['locked']['rev'] = 'other'
    if os.environ['UPDATE_MODE'] != 'unchanged':
        value['nodes']['devenv']['locked']['rev'] = 'new'
        Path('devenv.lock').write_text(json.dumps(value))
''')
            binary.chmod(0o755)
            result = subprocess.run(['bash', str(ROOT / 'ci/update-devenv-modules.sh')], cwd=root,
                                    env=dict(os.environ, PATH=str(root) + ':' + os.environ['PATH'],
                                             UPDATE_MODE=mode), capture_output=True, text=True, timeout=10)
            calls = [json.loads(line) for line in (root / 'calls').read_text().splitlines()]
            return result, calls

    def test_native_only_change_is_validated_and_reported(self):
        result, calls = self.run_update('native')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'changed=true\n')
        self.assertIn(['flake', 'check', '--accept-flake-config', '--no-build', '--no-write-lock-file'], calls)
        self.assertNotIn(['flake', 'update', 'nixpkgs', '--accept-flake-config'], calls)

    def test_unchanged_inputs_do_not_repeat_validation(self):
        result, calls = self.run_update('unchanged')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'changed=false\n')
        self.assertEqual(len(calls), 1)

    def test_split_native_application_inputs_fail_before_candidate_check(self):
        result, calls = self.run_update('split')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('changed=true', result.stdout)
        self.assertEqual(len(calls), 1)
