# SPDX-License-Identifier: Apache-2.0
"""Exercise the publication leaf and controller without writing public state."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CACHE = 'https://xen-orchestra-ce.cachix.org'
FAKE = '''
import json, os, pathlib, signal, sys, time
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
fixture = json.loads(pathlib.Path(os.environ['PUBLISH_FIXTURE']).read_text())
with open(os.environ['PUBLISH_CALLS'], 'a') as stream:
    stream.write(json.dumps([name, *args]) + '\\n')
if name == 'timeout':
    if args[:3] != ['--signal=TERM', '--kill-after=10s', '120s']:
        sys.exit(90)
    real = os.environ['PUBLISH_REAL_TIMEOUT']
    deadline = ['--signal=TERM', '--kill-after=0.05s', '0.15s'] if fixture.get('hang') else args[:3]
    os.execv(real, [real, *deadline, *args[3:]])
elif name == 'nix':
    if '--store' in args:
        if fixture.get('hang'):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            time.sleep(10)
        sys.stderr.write(fixture.get('stderr', ''))
        if fixture.get('exit'):
            sys.exit(fixture['exit'])
        value = fixture['remote']
        print(value if isinstance(value, str) else json.dumps(value))
    else:
        path = args[-1]
        print(json.dumps({path: {'narHash': fixture['local'][path]}}))
'''


class PublishReadback(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.native = self.work / 'bin'
        self.native.mkdir()
        for name in ('timeout', 'nix', 'nix-store', 'cachix', 'xo-nixpkg-publication-gate',
                     'xo-nixpkg-restore-products'):
            executable = self.native / name
            executable.write_text('#!' + sys.executable + '\n' + FAKE)
            executable.chmod(0o755)
        self.paths = ['/nix/store/' + str(i) * 32 + '-fixture-' + str(i) for i in range(8)]
        self.local = {path: 'sha256-' + 'A' * 43 + '=' for path in self.paths}
        entries = [{'storePath': path, 'narHash': value} for path, value in self.local.items()]
        self.product = {'products': dict(zip(('latest', 'stable', 'rolling'), entries[:3])),
                        'roots': {str(i): entry for i, entry in enumerate(entries[3:])},
                        'repository': 'closure-labs/xo-nixpkg', 'revision': 'a' * 40,
                        'assets': {}}
        (self.work / 'product.json').write_text(json.dumps(self.product))
        (self.work / 'scans.json').write_text('{}')
        self.calls = self.work / 'calls.jsonl'
        self.fixture = self.work / 'fixture.json'
        self.env = dict(os.environ, PATH=str(self.native) + os.pathsep + os.environ['PATH'],
                        PUBLISH_FIXTURE=str(self.fixture), PUBLISH_CALLS=str(self.calls),
                        XO_NIXPKG_EVIDENCE=str(self.work), CACHIX_AUTH_TOKEN='fixture-secret',
                        XO_NIXPKG_CACHIX_CACHE_NAME='xen-orchestra-ce',
                        XO_NIXPKG_CACHIX_CACHE_URL=CACHE,
                        PUBLISH_REAL_TIMEOUT=shutil.which('timeout'))

    def run_leaf(self, remote=None, **fixture):
        if remote is None:
            remote = {path: {'narHash': value} for path, value in self.local.items()}
        self.fixture.write_text(json.dumps(dict(fixture, remote=remote, local=self.local)))
        result = subprocess.run(['bash', str(ROOT / 'ci/publish.sh')], env=self.env,
                                text=True, capture_output=True, timeout=20)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        return result, calls

    def assert_rejected(self, remote=None, **fixture):
        result, calls = self.run_leaf(remote, **fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Public cache', result.stderr)
        self.assertEqual(sum(call[0] == 'cachix' for call in calls), 1)
        self.assertNotIn('fixture-secret', result.stdout + result.stderr)
        return result, calls

    def test_all_eight_paths_are_read_after_push_with_metadata_caches_disabled(self):
        result, calls = self.run_leaf()
        self.assertEqual(result.returncode, 0, result.stderr)
        remote = [call for call in calls if call[0] == 'nix' and '--store' in call]
        self.assertEqual(len(remote), 1)
        self.assertEqual(remote[0][-8:], self.paths)
        self.assertEqual(remote[0][remote[0].index('--store') + 1], CACHE)
        for option in ('narinfo-cache-positive-ttl', 'narinfo-cache-negative-ttl'):
            self.assertIn(['--option', option, '0'],
                          [remote[0][i:i + 3] for i in range(len(remote[0]))])
        self.assertLess(next(i for i, c in enumerate(calls) if c[0] == 'cachix'),
                        calls.index(remote[0]))

    def test_array_format_retains_exact_path_identity(self):
        result, _ = self.run_leaf([{'path': path, 'narHash': value}
                                   for path, value in reversed(list(self.local.items()))])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_same_path_wrong_hash_is_rejected(self):
        for path in self.paths:
            with self.subTest(path=path):
                remote = {item: {'narHash': value} for item, value in self.local.items()}
                remote[path]['narHash'] = 'sha256-' + 'B' * 43 + '='
                self.assert_rejected(remote)
                self.calls.unlink()

    def test_missing_null_and_extra_paths_are_rejected(self):
        for mode in ('missing', 'null', 'extra'):
            with self.subTest(mode=mode):
                remote = {path: {'narHash': value} for path, value in self.local.items()}
                if mode == 'missing':
                    del remote[self.paths[0]]
                elif mode == 'null':
                    remote[self.paths[0]] = None
                else:
                    remote['/nix/store/' + 'z' * 32 + '-extra'] = {'narHash': 'sha256-extra'}
                self.assert_rejected(remote)
                self.calls.unlink()

    def test_malformed_json_and_wrong_shapes_are_rejected(self):
        valid = json.dumps({path: {'narHash': value} for path, value in self.local.items()})
        for remote in ('not-json', '{}', 'null', '42', '[]', '{}\n' + valid,
                       valid + '\n' + valid,
                       [{'narHash': value} for value in self.local.values()]):
            with self.subTest(remote=remote):
                self.assert_rejected(remote)
                self.calls.unlink()

    def test_remote_failure_is_closed_and_diagnostics_do_not_expose_stderr(self):
        result, _ = self.assert_rejected(exit=1, stderr='fixture-secret untrusted remote details')
        self.assertNotIn('untrusted remote details', result.stderr)

    def test_stalled_remote_read_is_killed_and_rejected(self):
        self.assert_rejected(hang=True)

    def test_controller_does_not_checkpoint_or_handoff_after_readback_failure(self):
        remote = {path: {'narHash': value} for path, value in self.local.items()}
        remote[self.paths[0]]['narHash'] = 'sha256-' + 'B' * 43 + '='
        self.fixture.write_text(json.dumps(dict(remote=remote, local=self.local)))
        spec = importlib.util.spec_from_file_location('publication_readback_controller',
                                                     ROOT / 'ci/publication-controller.py')
        controller = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        def run(*args, **kwargs):
            if args == ('xo-nixpkg-publish',):
                return subprocess.run(['bash', str(ROOT / 'ci/publish.sh')],
                                      env=self.env, check=True, capture_output=True, text=True)
            self.assertEqual(args, ('xo-nixpkg-publication-gate',))
        with mock.patch.dict(os.environ, self.env), mock.patch.object(controller, 'run', run), \
                mock.patch.object(controller.subprocess, 'check_output', return_value='b' * 40), \
                mock.patch.object(controller, 'Journal') as journal, \
                mock.patch.object(controller, 'publish_handoff') as handoff:
            # A completed prior cache checkpoint cannot skip the actual leaf.
            journal.return_value.value = {'steps': [{'name': 'cache', 'state': 'complete'}]}
            with self.assertRaises(subprocess.CalledProcessError):
                controller.main()
            journal.return_value.complete.assert_not_called()
            handoff.assert_not_called()


if __name__ == '__main__':
    unittest.main()
