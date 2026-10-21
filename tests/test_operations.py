# SPDX-License-Identifier: Apache-2.0
"""Real monotonic deadlines clean up descendants; imported verification is required."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'ci/decisions' if (ROOT / 'ci').is_dir() else ROOT / 'nix/automation/decisions'
sys.path.insert(0, str(CORE))
import operations


class Budgets(unittest.TestCase):
    def test_nested_deadlines_propagate_remaining_time(self):
        with operations.budget(.4):
            first = operations.remaining(30)
            time.sleep(.03)
            with operations.budget(90):
                self.assertLess(operations.remaining(180), first - .01)
                result = operations.run([sys.executable, '-c',
                    'import os,time; print(float(os.environ["CI_OPERATION_DEADLINE"])-time.monotonic())'],
                    capture_output=True, text=True, timeout=30)
                self.assertLess(float(result.stdout), first)
        self.assertEqual(operations.remaining(30), 30)

    def test_timeout_kills_term_ignoring_descendant_and_removes_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            pidfile = Path(temporary) / 'descendant'
            script = '''import os,signal,subprocess,sys,time
child=subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)'])
open(sys.argv[1],'w').write(str(child.pid))
signal.signal(signal.SIGTERM,signal.SIG_IGN)
time.sleep(30)
'''
            started = time.monotonic()
            with patch.object(operations, 'KILL_GRACE', .05):
                with self.assertRaises(subprocess.TimeoutExpired):
                    operations.run([sys.executable, '-c', script, str(pidfile)], timeout=.2,
                                   capture_output=True)
            self.assertLess(time.monotonic() - started, 2)
            pid = int(pidfile.read_text())
            state = Path(f'/proc/{pid}/stat')
            try:
                observed = state.read_text().split()[2]
            except OSError:
                observed = None
            self.assertIn(observed, (None, 'Z'), 'descendant survived timeout')

    def test_nested_supervisor_cleans_detached_term_ignoring_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            pidfile = Path(temporary) / 'nested'
            transport = ('import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                         + 'open(' + repr(str(pidfile)) + ',"w").write(str(os.getpid())); time.sleep(30)')
            helper = ('import sys; sys.path.insert(0,' + repr(str(CORE)) + '); import operations; '
                      + 'operations.run([sys.executable,"-c",' + repr(transport)
                      + '],timeout=30,capture_output=True)')
            with patch.object(operations, 'KILL_GRACE', .05):
                with self.assertRaises(subprocess.TimeoutExpired):
                    operations.run([sys.executable, '-c', helper], timeout=.2, capture_output=True)
            time.sleep(.03)  # Allow delivery of the final SIGKILL before observing /proc.
            try:
                state = Path('/proc/' + pidfile.read_text() + '/stat').read_text().rpartition(')')[2].split()[0]
            except OSError:
                state = None
            self.assertIn(state, (None, 'Z'), 'nested transport survived outer cleanup')

    def test_required_import_budget_does_not_inherit_exhausted_optional_time(self):
        with operations.budget(.001):
            time.sleep(.005)
            with self.assertRaises(subprocess.TimeoutExpired):
                operations.remaining(180)
            with operations.budget(600, inherit=False):
                self.assertGreater(operations.remaining(600), 599)


if __name__ == '__main__':
    unittest.main()
