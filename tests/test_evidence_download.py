# SPDX-License-Identifier: Apache-2.0
"""Run both download leaves with isolated services and real short GNU deadlines."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'closure-labs/xo-nixpkg'
LEAVES = ('fetch-evidence.sh', 'reconcile-retained.sh')

FAKE = '''
import json, os, pathlib, signal, subprocess, sys, time
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
fixture = json.loads(pathlib.Path(os.environ['DOWNLOAD_FIXTURE']).read_text())
def record(value):
    with open(os.environ['DOWNLOAD_CALLS'], 'a') as stream:
        stream.write(json.dumps(value) + '\\n')
def evidence(directory):
    directory.mkdir(parents=True)
    (directory / 'scans.json').write_text(json.dumps({
        'producer': {'runId': fixture.get('evidence_run', 123),
                     'runAttempt': fixture.get('evidence_attempt', 2)},
        'expiresAt': '2099-01-01T00:00:00Z'}))
    (directory / 'product.json').write_text('{}')
record([name, *args])
if name == 'timeout':
    if args[:3] != ['--signal=TERM', '--kill-after=10s', '600s']:
        sys.exit(90)
    if fixture.get('real_deadline'):
        # Keep the production command/TERM behavior; shorten only the test clock.
        real = os.environ['DOWNLOAD_REAL_TIMEOUT']
        os.execv(real, [real, '--signal=TERM', '--kill-after=0.05s', '0.15s', *args[3:]])
    if fixture.get('download_exit'):
        directory = pathlib.Path(args[args.index('--dir') + 1])
        directory.mkdir(parents=True)
        (directory / 'partial-download').write_text('incomplete untrusted bytes')
        sys.exit(fixture['download_exit'])
    sys.exit(subprocess.run(args[3:], check=False).returncode)
elif name == 'gh' and args[0] == 'api':
    if '/actions/runs/' in args[1]:
        print(json.dumps(fixture['producer']))
    else:
        print(json.dumps({'workflow_runs': []}))
elif name == 'xo-nixpkg-inspect-qualification':
    print(json.dumps({'schema': 1, 'status': 'unretained'}))
elif name == 'gh' and args[:2] == ['run', 'download']:
    directory = pathlib.Path(args[args.index('--dir') + 1])
    if fixture.get('real_deadline'):
        directory.mkdir(parents=True)
        (directory / 'partial-download').write_text('incomplete untrusted bytes')
        if fixture.get('ignore_term'):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(10)
    evidence(directory)
elif name == 'retained.py':
    directory = pathlib.Path(os.environ['XO_NIXPKG_EVIDENCE'])
    # The fallback must receive a fresh directory and exact requested attempt.
    record(['fallback-state', directory.exists(), os.environ['QUALIFICATION_RUN'],
            os.environ['QUALIFICATION_ATTEMPT']])
    if directory.exists():
        sys.exit(91)
    if fixture.get('fallback_exit'):
        sys.exit(fixture['fallback_exit'])
    evidence(directory)
elif name in ('xo-nixpkg-publication-gate', 'xo-nixpkg-decision-publication'):
    sys.exit(fixture.get('gate_exit', 0))
'''


class EvidenceDownload(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sequence = 0
        self.producer = {'id': 123, 'run_attempt': 2, 'repository': {'full_name': REPOSITORY},
                         'head_repository': {'full_name': REPOSITORY}, 'head_sha': 'a' * 40,
                         'head_branch': 'main', 'path': '.github/workflows/qualification.yml',
                         'event': 'push', 'status': 'completed', 'conclusion': 'success',
                         'created_at': '2026-10-20T00:00:00Z'}

    def run_leaf(self, leaf, *, environment=None, **fixture):
        self.sequence += 1
        work = self.root / str(self.sequence)
        native = work / 'bin'
        native.mkdir(parents=True)
        for name in ('timeout', 'gh', 'oras', 'retained.py', 'xo-nixpkg-publication-gate',
                     'xo-nixpkg-decision-reconcile', 'xo-nixpkg-decision-publication', 'xo-nixpkg-inspect-qualification'):
            executable = native / name
            executable.write_text('#!' + sys.executable + '\n' + FAKE)
            executable.chmod(0o755)
        fixture_path = work / 'fixture.json'
        fixture_path.write_text(json.dumps(dict(fixture, producer=self.producer)))
        calls_path = work / 'calls.jsonl'
        env = dict(os.environ, PATH=str(native) + os.pathsep + os.environ['PATH'],
                   QUALIFICATION_RUN='123', QUALIFICATION_ATTEMPT='2',
                   GITHUB_REPOSITORY=REPOSITORY, GITHUB_ACTOR='fixture',
                   REGISTRY_TOKEN='fixture-registry-token',
                   XO_NIXPKG_EVIDENCE=str(work / 'evidence'),
                   XO_NIXPKG_RETAINED_FETCH_SOURCE=str(native / 'retained.py'),
                   DOWNLOAD_FIXTURE=str(fixture_path), DOWNLOAD_CALLS=str(calls_path),
                   DOWNLOAD_REAL_TIMEOUT=shutil.which('timeout'))
        env.pop('XO_NIXPKG_FETCH_FOR_RESCAN', None)
        env.update(environment or {})
        started = time.monotonic()
        result = subprocess.run(['bash', str(ROOT / 'ci' / leaf)], cwd=work, env=env,
                                capture_output=True, text=True, timeout=15)
        calls = [json.loads(line) for line in calls_path.read_text().splitlines()]
        return result, calls, time.monotonic() - started

    def assert_validation_reached(self, leaf, calls):
        if leaf == 'fetch-evidence.sh':
            self.assertEqual(sum(call[0] == 'xo-nixpkg-publication-gate' for call in calls), 1)
        else:
            decisions = [call[-1] for call in calls if call[0] == 'xo-nixpkg-decision-reconcile']
            self.assertEqual(decisions, ['security-findings', 'release-product'])
            self.assertEqual(sum(call[0] == 'xo-nixpkg-decision-publication' for call in calls), 1)

    def assert_no_validation(self, calls):
        self.assertFalse(any(call[0].startswith('xo-nixpkg-') for call in calls))
        self.assertFalse(any(call[:3] == ['gh', 'workflow', 'run'] for call in calls))

    def test_success_keeps_exact_artifact_and_validation_without_retained_fallback(self):
        for leaf in LEAVES:
            with self.subTest(leaf=leaf):
                result, calls, _ = self.run_leaf(leaf)
                self.assertEqual(result.returncode, 0, result.stderr)
                timeout = next(call for call in calls if call[0] == 'timeout')
                self.assertEqual(timeout[:8], ['timeout', '--signal=TERM', '--kill-after=10s',
                                             '600s', 'gh', 'run', 'download', '123'])
                self.assertIn('qualified-products-123-2', timeout)
                self.assertEqual(sum(call[:3] == ['gh', 'run', 'download'] for call in calls), 1)
                self.assertFalse(any(call[0] in ('retained.py', 'fallback-state') for call in calls))
                self.assert_validation_reached(leaf, calls)

    def test_timeout_kill_and_ordinary_failure_clean_partial_files_before_exact_fallback(self):
        for leaf in LEAVES:
            for code in (124, 137, 1):
                with self.subTest(leaf=leaf, code=code):
                    result, calls, _ = self.run_leaf(leaf, download_exit=code)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual([call for call in calls if call[0] == 'fallback-state'],
                                     [['fallback-state', False, '123', '2']])
                    self.assertEqual(sum(call[0] == 'timeout' for call in calls), 1)
                    self.assert_validation_reached(leaf, calls)

    def test_failed_authenticated_fallback_cannot_reach_admission_or_dispatch(self):
        for leaf in LEAVES:
            with self.subTest(leaf=leaf):
                result, calls, _ = self.run_leaf(leaf, download_exit=124, fallback_exit=2)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(sum(call[0] == 'retained.py' for call in calls), 1)
                self.assert_no_validation(calls)

    def test_wrong_run_or_attempt_fails_closed_for_downloaded_and_retained_evidence(self):
        for leaf in LEAVES:
            for code in (0, 124):
                for identity in ({'evidence_run': 124}, {'evidence_attempt': 1}):
                    with self.subTest(leaf=leaf, code=code, identity=identity):
                        result, calls, _ = self.run_leaf(leaf, download_exit=code, **identity)
                        self.assertNotEqual(result.returncode, 0)
                        self.assert_no_validation(calls)

    def test_requested_stale_attempt_rejected_before_publisher_download(self):
        result, calls, _ = self.run_leaf('fetch-evidence.sh', environment={'QUALIFICATION_ATTEMPT': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] == 'timeout' for call in calls))
        self.assert_no_validation(calls)

    def test_fallback_still_obeys_live_admission_failure(self):
        for leaf in LEAVES:
            with self.subTest(leaf=leaf):
                result, calls, _ = self.run_leaf(leaf, download_exit=124, gate_exit=2)
                if leaf == 'fetch-evidence.sh':
                    self.assertEqual(result.returncode, 2)
                self.assert_validation_reached(leaf, calls)
                self.assertFalse(any(call[:3] == ['gh', 'workflow', 'run'] for call in calls))

    def test_real_gnu_timeout_terminates_stalled_and_term_ignoring_downloads(self):
        for leaf in LEAVES:
            for ignore in (False, True):
                with self.subTest(leaf=leaf, ignore_term=ignore):
                    result, calls, elapsed = self.run_leaf(leaf, real_deadline=True, ignore_term=ignore)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertLess(elapsed, 5)
                    self.assertEqual([call for call in calls if call[0] == 'fallback-state'],
                                     [['fallback-state', False, '123', '2']])
                    self.assert_validation_reached(leaf, calls)


if __name__ == '__main__':
    unittest.main()
