"""Synthetic fixtures pin policy outcomes independently of engine performance."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('scanner_fixtures', ROOT / 'ci/scanner-fixtures.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ScannerFixtures(unittest.TestCase):
    def test_existing_policy_exact_coverage(self):
        files = mod.fixture_files()
        rows = mod.expected_findings(files)
        self.assertEqual(len(rows), mod.KEY_COUNT + 3)
        compact, pretty, external = files
        self.assertEqual(sum(row[1] == compact for row in rows), mod.KEY_COUNT + 1)
        self.assertEqual(sum(row[1] == pretty for row in rows), 1)
        self.assertEqual(sum(row[1] == external for row in rows), 1)
        for content in files.values():
            json.loads(content)
        self.assertGreater(len(files[compact]), mod.PADDING_BYTES)

    def test_cli_success_summary_is_non_authoritative(self):
        summary = {'schema': 1, 'status': 'success', 'authorityClaim': False,
                   'reuseEligible': False, 'findings': 35}
        with patch.object(mod.sys, 'argv', ['scanner-fixtures', '--scanner', 'fake', '--config', 'policy']), \
                patch.object(mod, 'verify', return_value=(summary, [])), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(mod.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), summary)

    def test_unredacted_or_invalid_reports_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report'
            for content in ('{}', '[{}]', '[null]', '[1]', 'broken', '[{"Secret":"unredacted"}]'):
                path.write_text(content)
                with self.assertRaises(mod.FixtureError):
                    mod.report_signatures(path)

    def test_timeout_is_sanitized(self):
        with patch.object(mod.operations, 'run', side_effect=mod.subprocess.TimeoutExpired('private-output', 1)):
            with self.assertRaisesRegex(mod.FixtureError, '^fixture subprocess failed or timed out$'):
                mod.run_quiet(['fake'], ROOT)

    def test_output_and_environment_are_bounded(self):
        with patch.dict(os.environ, {'GITLEAKS_CONFIG': '/wrong', 'GIT_DIR': '/wrong'}), patch.object(mod.operations, 'run') as run:
            run.return_value.returncode = 1
            self.assertEqual(mod.run_quiet(['fake'], ROOT), 1)
            options = run.call_args.kwargs
            self.assertEqual(options['stdout'], mod.subprocess.DEVNULL)
            self.assertEqual(options['stderr'], mod.subprocess.DEVNULL)
            self.assertEqual(options['timeout'], mod.TIMEOUT)
            self.assertNotIn('GITLEAKS_CONFIG', options['env'])
            self.assertNotIn('GIT_DIR', options['env'])
            self.assertIs(options['preexec_fn'], mod._limits)

    def test_unexpected_scanner_exit_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'scanner'
            executable.write_bytes(b'synthetic executable')
            with patch.object(mod, 'run_quiet', return_value=0):
                with self.assertRaisesRegex(mod.FixtureError, 'expected findings status'):
                    mod.verify(executable, ROOT / '.gitleaks.toml')

    def test_missing_finding_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'scanner'
            executable.write_bytes(b'synthetic executable')
            with patch.object(mod, 'run_quiet', side_effect=[0, 0, 0, 1]), patch.object(mod, 'report_signatures', return_value=[]):
                with self.assertRaisesRegex(mod.FixtureError, 'coverage mismatch'):
                    mod.verify(executable, ROOT / '.gitleaks.toml')

    @unittest.skipUnless(os.environ.get('SCANNER_FIXTURE_ENGINE'), 'explicit native scanner required')
    def test_native_exact_engine(self):
        summary, rows = mod.verify(os.environ['SCANNER_FIXTURE_ENGINE'], ROOT / '.gitleaks.toml')
        self.assertEqual(summary['status'], 'success')
        self.assertFalse(summary['authorityClaim'])
        self.assertFalse(summary['reuseEligible'])
        self.assertEqual(summary['findings'], len(rows))
        self.assertEqual(len(summary['engine_sha256']), 64)


if __name__ == '__main__':
    unittest.main()
