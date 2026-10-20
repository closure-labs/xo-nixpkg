#!/usr/bin/env python3
"""Real subprocess failures retain bounded classifications, never raw secrets."""
import json
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci/decisions'))
import decision_packets as mod


class RegistryCommand(unittest.TestCase):
    def run_child(self, source, **kwargs):
        return mod.command([sys.executable, '-c', source, 'https://user:argv-secret@private.invalid/token'], **kwargs)

    def failure(self, source, **kwargs):
        with self.assertRaises(ValueError) as raised:
            self.run_child(source, **kwargs)
        message = str(raised.exception)
        for private in ('stderr-secret', 'argv-secret', 'private.invalid', 'https://', 'Authorization', 'Bearer', 'ghp_'):
            self.assertNotIn(private, message)
        self.assertTrue(raised.exception.__suppress_context__)
        return json.loads(message.removeprefix('Registry command failed: '))

    def test_success_retains_exact_stdout_and_suppresses_stderr(self):
        self.assertEqual(self.run_child('import sys;sys.stderr.write("stderr-secret");sys.stdout.buffer.write(b"{\\\"ok\\\":true}")'), b'{"ok":true}')

    def test_registry_write_denial_is_classified_without_credentials_or_url(self):
        source = 'import sys;sys.stderr.write("Error: PUT https://user:stderr-secret@private.invalid/v2/?token=ghp_secret Authorization: Bearer stderr-secret status code 403: denied: permission_denied: write_package");sys.exit(1)'
        value = self.failure(source)
        self.assertEqual(value['exitCode'], 1)
        self.assertEqual(value['httpStatus'], [403])
        self.assertIn('registry-write-denied', value['categories'])
        self.assertEqual(value['fileLimitBytes'], 2 * 1024**2)
        self.assertEqual(value['operation'], 'registry-command')

    def test_large_stderr_is_drained_and_tail_error_remains_bounded(self):
        value = self.failure('import os,sys;os.write(2,b"stderr-secret"*300000);os.write(2,b"\\nHTTP/1.1 429 Too Many Requests");sys.exit(1)')
        self.assertGreater(value['stderrBytes'], 2 * 1024**2)
        self.assertTrue(value['stderrTruncated'])
        self.assertEqual(value['httpStatus'], [429])
        self.assertIn('rate-limited', value['categories'])
        self.assertLess(len(json.dumps(value)), 1000)

    def test_output_and_created_file_limits_remain_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'oversized'
            source = 'import os;f=open("oversized","wb");f.write(b"x"*(3*1024**2));f.flush()'
            value = self.failure(source, cwd=temporary)
            self.assertIn('file-size-limit', value['categories'])
            self.assertLessEqual(path.stat().st_size, 2 * 1024**2)
            # An explicitly authenticated blob limit may exceed stdout's cap.
            self.assertEqual(self.run_child(source, cwd=temporary, max_file_bytes=4 * 1024**2), b'')
        with self.assertRaisesRegex(ValueError, 'output exceeds bound'):
            self.run_child('import os;os.write(1,b"x"*(3*1024**2))', max_file_bytes=4 * 1024**2)

    def test_timeout_and_signal_do_not_echo_command(self):
        with mock.patch.object(mod, 'COMMAND_TIMEOUT', .15):
            value = self.failure('import sys,time;sys.stderr.write("stderr-secret");sys.stderr.flush();time.sleep(20)')
        self.assertIn('timeout', value['categories'])
        value = self.failure('import os,signal;signal.signal(signal.SIGXFSZ, signal.SIG_DFL);os.kill(os.getpid(), signal.SIGXFSZ)')
        self.assertEqual(value['signal'], signal.SIGXFSZ)
        self.assertIn('file-size-limit', value['categories'])

    def test_actual_oras_operation_and_start_failure_stay_sanitized(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'oras'
            path.write_text('#!' + sys.executable + '\nimport sys\nsys.stderr.write("status code 403 permission_denied: write_package stderr-secret")\nsys.exit(1)\n')
            path.chmod(0o700)
            with self.assertRaises(ValueError) as raised:
                mod.command([str(path), 'push', 'https://user:argv-secret@private.invalid'])
            value = json.loads(str(raised.exception).removeprefix('Registry command failed: '))
            self.assertEqual(value['operation'], 'oras-push')
            self.assertIn('registry-write-denied', value['categories'])
            self.assertNotIn('secret', str(raised.exception))
            with self.assertRaises(ValueError) as raised:
                mod.command([str(Path(temporary) / 'argv-secret-missing-executable'), 'https://private.invalid'])
            self.assertIn('start-failed', str(raised.exception))
            self.assertNotIn('secret', str(raised.exception))
            self.assertNotIn('private.invalid', str(raised.exception))
            self.assertTrue(raised.exception.__suppress_context__)

    def test_unknown_stderr_is_never_reflected_and_operation_is_allowlisted(self):
        value = self.failure('import sys;sys.stderr.write("unrecognized stderr-secret ghp_sensitive_value https://private.invalid");sys.exit(2)')
        self.assertEqual(value['categories'], ['unclassified'])
        self.assertEqual(value['exitCode'], 2)
        self.assertEqual(mod.command_operation(['oras', 'push', 'private-secret']), 'oras-push')
        self.assertEqual(mod.command_operation(['/unexpected/secret-tool', 'secret-command']), 'registry-command')


if __name__ == '__main__':
    unittest.main()
