# SPDX-License-Identifier: Apache-2.0
"""Exercise scheduling, ordered diagnostics, cancellation and bounded concurrency."""
import json
import os
from pathlib import Path
import signal
import sys
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
FAKE = r'''#!/usr/bin/env python3
import fcntl, json, os, signal, sys, time
from pathlib import Path
root = Path(os.environ['PARALLEL_FIXTURE'])
name = sys.argv[-1].rsplit('.', 1)[-1]
def record(event):
    with (root / 'events').open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.write(json.dumps([event, name, os.getpid()]) + '\n')
        stream.flush()
def stop(*_):
    record('stopped')
    sys.exit(143)
signal.signal(signal.SIGTERM, stop)
record('start')
time.sleep(float(os.environ.get('DELAY_' + name.upper(), '0.15')))
record('end')
if name == os.environ.get('FAIL_NAME'): sys.exit(1)
print('/nix/store/' + name)
'''


class ParallelRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fake = self.root / 'nix'
        self.fake.write_text(FAKE.replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
        self.fake.chmod(0o700)
        self.plan = self.root / 'plan.json'
        self.plan.write_text(json.dumps({'schemaVersion': 2, 'name': 'parallel', 'targets': [
            {'name': name, 'attribute': 'checks.x86_64-linux.' + name, 'link': 'result-' + name}
            for name in ['first', 'second', 'third']]}))
        self.environment = dict(os.environ, FLAKE_PLAN_RUNNER_NIX=str(self.fake),
                                FLAKE_PLAN_LINK_ROOT=str(self.root), PARALLEL_FIXTURE=str(self.root))
        self.args = ['bash', str(ROOT / 'nix/flake-plan-runner.sh'), '--plan-file', str(self.plan),
                     '--manifest', str(self.root / 'manifest.json'), '--timings', str(self.root / 'timings.json')]

    def events(self):
        return [json.loads(line) for line in (self.root / 'events').read_text().splitlines()]

    def run_plan(self, jobs='2', **environment):
        return subprocess.run([*self.args, '--jobs', jobs], env=dict(self.environment, **environment),
                              capture_output=True, text=True, timeout=15)

    def test_refills_finished_slot_and_keeps_manifest_in_plan_order(self):
        result = self.run_plan(DELAY_FIRST='1.2', DELAY_SECOND='0.1', DELAY_THIRD='0.15')
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events()
        pairs = [(event, name) for event, name, _ in events]
        self.assertLess(pairs.index(('start', 'third')), pairs.index(('end', 'first')))
        active = peak = 0
        for event, _, _ in events:
            active += 1 if event == 'start' else -1
            peak = max(peak, active)
            self.assertLessEqual(active, 2)
        self.assertEqual((peak, active), (2, 0))
        manifest = json.loads((self.root / 'manifest.json').read_text())
        self.assertEqual([item['name'] for item in manifest['results']], ['first', 'second', 'third'])
        self.assertEqual(manifest['failureCount'], 0)
        self.assertTrue(all((self.root / ('result-' + name)).is_symlink() for name in ['first', 'second', 'third']))

    def test_failure_retains_all_diagnostics_without_promoting_links(self):
        result = self.run_plan(FAIL_NAME='second')
        self.assertNotEqual(result.returncode, 0)
        manifest = json.loads((self.root / 'manifest.json').read_text())
        self.assertEqual([item['status'] for item in manifest['results']], ['success', 'failure', 'success'])
        self.assertEqual(manifest['failureCount'], 1)
        self.assertFalse(any(self.root.glob('result-*')))
        self.assertEqual(len(json.loads((self.root / 'timings.json').read_text())['results']), 3)

    def test_serial_default_and_invalid_bounds(self):
        result = self.run_plan('1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([(e, n) for e, n, _ in self.events()], [
            (event, name) for name in ['first', 'second', 'third'] for event in ['start', 'end']])
        for value in ['0', '3', '-1', '2;false']:
            self.assertEqual(self.run_plan(value).returncode, 2)

    def test_cancellation_stops_owned_builds_without_partial_success(self):
        with subprocess.Popen([*self.args, '--jobs', '2'], env=dict(self.environment,
                DELAY_FIRST='30', DELAY_SECOND='30'), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if (self.root / 'events').exists() and len(self.events()) >= 2:
                    break
                time.sleep(0.02)
            else:
                process.kill()
                self.fail('two builds did not start')
            process.send_signal(signal.SIGTERM)
            _, errors = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 143, errors.decode())
        events = self.events()
        self.assertEqual({name for event, name, _ in events if event == 'stopped'}, {'first', 'second'})
        self.assertFalse((self.root / 'manifest.json').exists())
        self.assertFalse(any(self.root.glob('result-*')))


if __name__ == '__main__':
    unittest.main()
