# SPDX-License-Identifier: Apache-2.0
"""Diagnostic execution is bounded, credential-free, and never admission proof."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('scanner_evidence', ROOT / 'ci/secret-scan-evidence.py')
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class ScannerEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {'PATH': '/trusted/bin', 'XO_NIXPKG_SECRET_SCANNER': '/nix/store/pinned/bin/gitleaks',
                    'XO_NIXPKG_SECRET_SCANNER_IDENTITY': '/nix/store/pinned-identity',
                    'XO_NIXPKG_SCANNER_FIXTURE_SOURCE': '/trusted/fixtures.py',
                    'XO_NIXPKG_HISTORY_SCAN_SOURCE': '/trusted/history.py'}

    def test_sanitizes_credentials_and_user_configuration(self):
        inherited = dict(self.env, GH_TOKEN='private', GITHUB_TOKEN='private',
                         NIX_CONFIG='access-tokens = private', GIT_CONFIG_GLOBAL='/private',
                         GITLEAKS_CONFIG='/private', AWS_SECRET_ACCESS_KEY='private',
                         ACTIONS_ID_TOKEN_REQUEST_TOKEN='private')
        env = mod.environment(self.root / 'home', inherited)
        for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'GITLEAKS_CONFIG', 'AWS_SECRET_ACCESS_KEY',
                    'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'GITHUB_OUTPUT'):
            self.assertNotIn(key, env)
        self.assertNotIn('private', json.dumps(env))
        self.assertIn('access-tokens =\n', env['NIX_CONFIG'])
        self.assertIn('builders =\n', env['NIX_CONFIG'])
        self.assertEqual(env['NIX_USER_CONF_FILES'], '/dev/null')

    def test_all_stages_execute_even_history_blocks_and_no_authority(self):
        outcomes = [dict(stage=name, status='blocked' if name == 'complete-history' else 'success')
                    for name in mod.STAGES]
        with patch.object(mod, 'clean_checkout'), \
             patch.object(mod, 'stage', side_effect=outcomes) as stage:
            result = mod.run(self.root, self.root / 'out', self.env)
        self.assertEqual(stage.call_count, 3)
        self.assertEqual(result['status'], 'blocked')
        self.assertIs(result['authorityClaim'], False)
        self.assertIs(result['reuseEligible'], False)
        self.assertEqual([call.args[2] for call in stage.call_args_list], [90, 1260, 600])
        self.assertEqual(json.loads((self.root / 'out/scanner-evidence.json').read_text()), result)

    def test_introduced_scope_is_explicit_and_not_full_audit_claim(self):
        outcomes = [dict(stage=name, status='success')
                    for name in ('engine-fixtures', 'introduced-history', 'security-fixtures')]
        with patch.object(mod, 'clean_checkout'), patch.object(mod, 'stage', side_effect=outcomes) as stage:
            result = mod.run(self.root, self.root / 'out', self.env,
                             'introduced', 'a' * 40, 'b' * 40)
        history = stage.call_args_list[1].args
        self.assertEqual(history[0], 'introduced-history')
        self.assertEqual(history[1][-6:],
                         ['--mode', 'introduced', '--base-sha', 'a' * 40, '--head-sha', 'b' * 40])
        self.assertEqual(result['status'], 'success')
        self.assertNotIn('complete-history', json.dumps(result))

    def test_scope_requires_exact_inputs(self):
        for mode, base, head in [('introduced', None, None), ('introduced', 'main', 'b' * 40),
                                  ('full', 'a' * 40, 'b' * 40), ('unknown', None, None)]:
            with self.subTest(mode=mode, base=base), self.assertRaises(ValueError):
                mod.run(self.root, self.root / 'out', self.env, mode, base, head)

    def test_dirty_checkout_fails_before_stages(self):
        with patch.object(mod, 'clean_checkout', side_effect=ValueError('dirty')), \
             patch.object(mod, 'stage') as stage, self.assertRaises(ValueError):
            mod.run(self.root, self.root / 'out', self.env)
        stage.assert_not_called()

    def test_stage_timeout_is_fixed_category_not_raw_exception(self):
        with patch.object(mod.operations, 'run', side_effect=subprocess.TimeoutExpired(['private'], 1)):
            result = mod.stage('test', [], 1, self.root, {}, self.root, True)
        self.assertEqual(result['reason'], 'timeout')
        self.assertNotIn('private', json.dumps(result))

    def test_nonzero_stage_does_not_parse_or_publish_output(self):
        with patch.object(mod.operations, 'run', return_value=subprocess.CompletedProcess([], 1)):
            result = mod.stage('test', [], 1, self.root, {}, self.root, True)
        self.assertEqual(result['status'], 'blocked')
        self.assertFalse((self.root / 'test.json').exists())

    def test_json_stage_rejects_authority_claims(self):
        def run(*args, **kw):
            kw['stdout'].write(json.dumps({'status': 'success', 'authorityClaim': True,
                                           'reuseEligible': False}).encode())
            return subprocess.CompletedProcess([], 0)
        with patch.object(mod.operations, 'run', side_effect=run):
            result = mod.stage('test', [], 1, self.root, {}, self.root, True)
        self.assertEqual(result['status'], 'blocked')

    def test_history_failure_keeps_only_bounded_safe_diagnostics(self):
        value = {'schema': 1, 'stage': 'history-batch', 'status': 'blocked',
                 'batch': 2, 'commits': 8, 'reason': 'timeout', 'seconds': 600.1}
        def run(*args, **kw):
            kw['stdout'].write((json.dumps(value) + '\n').encode())
            return subprocess.CompletedProcess([], 1)
        with patch.object(mod.operations, 'run', side_effect=run):
            result = mod.stage('complete-history', [], 1, self.root, {}, self.root, True)
        self.assertEqual(result['status'], 'blocked')
        report = json.loads((self.root / 'history-failures.json').read_text())
        self.assertEqual(report['batches'][0]['batch'], 2)
        self.assertIs(report['authorityClaim'], False)
        for field, bad in (('reason', 'private-secret'), ('reason', {}), ('reason', []),
                           ('extra', 'private-secret'),
                           ('seconds', float('nan')), ('batch', -1), ('commits', 999)):
            with self.subTest(field=field), tempfile.TemporaryFile() as output:
                output.write(json.dumps(dict(value, **{field: bad})).encode())
                self.assertEqual(mod.history_failures(output), [])

    def test_workflow_bootstrap_remains_required_and_read_only(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        preflight = workflow.split('  preflight:', 1)[1].split('\n  validate:', 1)[0]
        self.assertIn("github-token: ''", preflight)
        self.assertIn('env -i PATH=', preflight)
        self.assertIn('.#secret-scan-evidence', preflight)
        self.assertIn('persist-credentials: false', preflight)
        self.assertNotIn('secrets.', preflight)
        self.assertNotIn(': write', preflight)
        self.assertNotIn('continue-on-error', preflight)
        self.assertIn('needs: [classify, preflight]', workflow)
        self.assertIn("needs.preflight.result == 'success'", workflow)


if __name__ == '__main__':
    unittest.main()
