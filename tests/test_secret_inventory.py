#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the real default scanner with the narrow canonical-ledger exception."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / '.gitleaks.toml'
KEY = hashlib.sha256(b'public canonical vulnerability identity fixture').hexdigest()
LEDGER = 'automation/decisions/security/' + 'a' * 64 + '.json'
LINE = '          "key": "' + KEY + '",\n'
# Deliberately synthetic credentials, assembled to avoid embedding a token in
# this test source. They must remain detectable in every tested ledger path.
FAKE = 'gh' + 'p_' + ''.join(('7ByR9KxW3cTa', '8HsM2nVp6QdE', '4LfZ0uJ5iGoS'))


class SecretInventoryTests(unittest.TestCase):
    def setUp(self):
        self.scanner = os.environ.get('GITLEAKS_BIN') or shutil.which('gitleaks')
        if not self.scanner:
            self.fail('The pinned native gitleaks executable is required')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def scan(self, files, mode='dir'):
        for name, content in files.items():
            target = self.directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        report = self.directory.parent / (self.directory.name + '-redacted.json')
        self.addCleanup(lambda: report.unlink(missing_ok=True))
        result = subprocess.run([self.scanner, mode, '--config', str(CONFIG), '--redact',
                                 '--no-banner', '--report-format', 'json', '--report-path', str(report),
                                 '.'], capture_output=True, text=True, timeout=60,
                                cwd=self.directory)
        self.assertIn(result.returncode, (0, 1), 'Native scanner failed (output withheld)')
        findings = json.loads(report.read_text()) if report.exists() else []
        # Never print a finding/match/secret in assertion diagnostics.
        return result.returncode, [(finding['RuleID'], finding['File']) for finding in findings]

    def test_only_canonical_finding_key_is_exempt(self):
        status, findings = self.scan({LEDGER: "{\n" + LINE + "}\n"})
        self.assertEqual(status, 0)
        self.assertEqual(findings, [])

    def test_neighbor_credentials_and_default_service_rules_remain_enabled(self):
        status, findings = self.scan({LEDGER: LINE + '          "api_key": "' + KEY + '",\n'
                                     + '          "token": "' + FAKE + '",\n'})
        self.assertEqual(status, 1)
        self.assertIn('github-pat', {rule for rule, _ in findings})
        self.assertIn('generic-api-key', {rule for rule, _ in findings})

    def test_path_and_complete_line_are_both_required(self):
        alternatives = [
            ('source.py', LINE),
            ('automation/decisions/releases/' + 'a' * 64 + '.json', LINE),
            ('automation/decisions/security/not-a-canonical-id.json', LINE),
            (LEDGER, LINE.replace('"key"', '"api_key"')),
            (LEDGER, LINE.replace(KEY, KEY + 'a')),
            (LEDGER, LINE.replace(KEY, KEY[:-1])),
            (LEDGER, LINE.rstrip('\n') + ' "api_key": "' + FAKE + '"\n'),
            (LEDGER, LINE.replace(KEY, FAKE)),
            (LEDGER, LINE.replace(KEY, KEY + FAKE)),
        ]
        for index, (path, content) in enumerate(alternatives):
            with self.subTest(case=index):
                for child in self.directory.iterdir():
                    shutil.rmtree(child) if child.is_dir() else child.unlink()
                status, findings = self.scan({path: content})
                self.assertEqual(status, 1)
                self.assertTrue(findings)

    def test_deleted_credentials_remain_detectable_in_git_history(self):
        def git(*args):
            subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(self.directory), *args],
                           check=True, capture_output=True, text=True)
        git('init', '--quiet')
        git('config', 'user.name', 'Secret inventory fixture')
        git('config', 'user.email', 'fixture@example.invalid')
        ledger = self.directory / LEDGER
        ledger.parent.mkdir(parents=True)
        ledger.write_text('{\n' + LINE + '}\n')
        git('add', LEDGER)
        target = self.directory / 'source.py'
        target.write_text('api_key = "' + FAKE + '"\n')
        git('add', 'source.py')
        git('commit', '--quiet', '-m', 'synthetic scanner fixture')
        target.write_text('no credential remains\n')
        git('add', 'source.py')
        git('commit', '--quiet', '-m', 'remove synthetic fixture')
        status, findings = self.scan({}, mode='git')
        self.assertEqual(status, 1)
        self.assertIn('github-pat', {rule for rule, _ in findings})
        self.assertTrue(all(path == 'source.py' for _, path in findings))


if __name__ == '__main__':
    unittest.main()
