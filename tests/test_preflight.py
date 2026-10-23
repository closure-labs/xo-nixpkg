# SPDX-License-Identifier: Apache-2.0
"""Preflight is a same-run prerequisite, with independent runtime attestation."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
NATIVE_RUN = subprocess.run
YQ = shutil.which('yq') or 'yq'
SPEC = importlib.util.spec_from_file_location('preflight_reuse', ROOT / 'ci/build-reuse.py')
reuse = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reuse)


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate, self.controller, self.evidence = (self.root / name for name in ('candidate', 'controller', 'evidence'))
        for root in (self.candidate, self.controller):
            (root / '.github/workflows').mkdir(parents=True)
            (root / reuse.WORKFLOW).write_text('protected fixture workflow')
        (self.controller / 'ci').mkdir()
        (self.controller / 'ci/classifier.json').write_text(json.dumps({'preflightTargets': ['repository-policy']}))
        self.cheap = {'name': 'repository-policy', 'attribute': 'checks.x86_64-linux.repository-policy'}
        self.runtime = {'name': 'xo-latest', 'attribute': 'checks.x86_64-linux.xo-latest'}
        self.plan = {'schemaVersion': 2, 'name': 'fixture', 'targets': [self.cheap, self.runtime]}
        self.environment = {'PREPARED_CI_WORKFLOW': json.dumps({'jobs': {'validate': {'plan': self.plan}}}),
                            'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2',
                            'XO_NIXPKG_TRUSTED_PLAN_NIX': '/nix/store/fixture/bin/xo-nixpkg-candidate-nix',
                            'XO_NIXPKG_PLAN_RUNNER': '/nix/store/fixture/bin/plan-runner',
                            'GH_TOKEN': 'must-not-enter-candidate-environment'}
        self.patch(patch.dict(os.environ, self.environment, clear=True))
        self.patch(patch.object(reuse, 'git', side_effect=self.git))
        self.patch(patch.object(reuse, 'child_environment', return_value={'PATH': '/trusted/bin'}))
        self.native = self.patch(patch.object(reuse, 'nix', return_value=''))
        self.scan = self.patch(patch.object(reuse.operations, 'run'))
        self.runner = self.patch(patch.object(reuse.subprocess, 'run', side_effect=self.run_plan))
        self.restore = self.patch(patch.object(reuse, 'restore'))

    def patch(self, value):
        self.addCleanup(value.stop)
        return value.start()

    def git(self, root, *arguments):
        if arguments == ('rev-parse', '--is-shallow-repository'):
            return 'false'
        if arguments == ('rev-parse', 'HEAD^{tree}'):
            return 'c' * 40
        return ('a' if root == self.candidate else 'b') * 40

    def run_plan(self, arguments, **kwargs):
        self.assertNotIn('GH_TOKEN', kwargs['env'])
        plan = json.loads(Path(arguments[arguments.index('--plan-file') + 1]).read_text())
        manifest = {'schemaVersion': 2, 'plan': plan['name'], 'targetCount': len(plan['targets']), 'failureCount': 0,
                    'results': [dict(target, status='success', outputs=[]) for target in plan['targets']]}
        reuse.write_json(Path(arguments[arguments.index('--manifest') + 1]), manifest)
        reuse.write_json(Path(arguments[arguments.index('--timings') + 1]), {
            'schemaVersion': 1, 'plan': plan['name'], 'results': [dict(target, status='success', elapsedSeconds=1) for target in plan['targets']]})

    def preflight(self):
        reuse.validate(self.candidate, self.controller, self.evidence, phase='preflight')

    def test_shared_checks_and_history_precede_runtime_without_duplicate_selected_targets(self):
        self.preflight()
        self.scan.assert_called_once()
        self.assertEqual(self.scan.call_args.args[0], ['gitleaks', 'git', '--redact', '--no-banner'])
        self.assertNotIn('GH_TOKEN', self.scan.call_args.kwargs['env'])
        self.assertEqual(self.native.call_args_list[0].args[-1], 'git+file://' + str(self.candidate) + '#lib.ciSecurityFixtures.x86_64-linux')
        self.restore.assert_not_called()
        self.assertEqual(self.runner.call_count, 1)
        self.native.reset_mock()
        reuse.validate(self.candidate, self.controller, self.evidence, phase='runtime', preflight=self.evidence)
        self.assertEqual(self.runner.call_count, 2)
        self.scan.assert_called_once()
        self.native.assert_not_called()
        self.restore.assert_called_once()
        manifests = [json.loads((self.evidence / (phase + '.json')).read_text())['results'] for phase in ('preflight', 'runtime')]
        self.assertEqual([[item['name'] for item in results] for results in manifests], [['repository-policy'], ['xo-latest']])

    def test_identity_changes_cannot_reuse_preflight(self):
        self.preflight()
        binding = json.loads((self.evidence / 'preflight-binding.json').read_text())
        for field in ('source', 'tree', 'controller', 'planSha256', 'runId', 'runAttempt', 'workflowSha256', 'launcherSha256', 'repository', 'historyScan', 'securityFixtures'):
            changed = dict(binding, **{field: 999 if field in ('runId', 'runAttempt') else 'changed'})
            reuse.write_json(self.evidence / 'preflight-binding.json', changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                reuse.validate(self.candidate, self.controller, self.evidence, phase='runtime', preflight=self.evidence)
        self.restore.assert_not_called()
        self.assertEqual(self.runner.call_count, 1)

    def test_failed_manifest_or_missing_timing_blocks_runtime_even_with_matching_file_hashes(self):
        self.preflight()
        manifest_path = self.evidence / 'preflight.json'
        value = json.loads(manifest_path.read_text())
        value['results'][0]['status'] = 'failure'
        reuse.write_json(manifest_path, value)
        binding_path = self.evidence / 'preflight-binding.json'
        binding = json.loads(binding_path.read_text())
        binding['files']['preflight.json'] = reuse.digest(manifest_path)
        reuse.write_json(binding_path, binding)
        with self.assertRaises(ValueError):
            reuse.verify_preflight(self.evidence, self.candidate, self.controller, self.plan, [self.cheap])
        (self.evidence / 'preflight-timings.json').unlink()
        with self.assertRaises(ValueError):
            reuse.verify_preflight(self.evidence, self.candidate, self.controller, self.plan, [self.cheap])

    def test_secret_finding_shared_fixture_failure_and_shallow_history_fail_before_runtime(self):
        self.preflight()
        self.runner.reset_mock()
        self.native.reset_mock()
        self.scan.side_effect = subprocess.CalledProcessError(1, ['gitleaks'])
        with self.assertRaises(subprocess.CalledProcessError):
            self.preflight()
        self.native.assert_not_called()
        self.scan.side_effect = None
        self.native.side_effect = subprocess.CalledProcessError(1, ['nix', 'build', '#lib.ciSecurityFixtures.x86_64-linux'])
        with self.assertRaises(subprocess.CalledProcessError):
            self.preflight()
        self.runner.assert_not_called()
        self.restore.assert_not_called()
        self.assertFalse((self.evidence / 'preflight-binding.json').exists())
        with patch.object(reuse, 'git', return_value='true'), self.assertRaises(ValueError):
            self.preflight()

    def test_docs_only_still_requires_security_fixtures_and_complete_history(self):
        os.environ['PREPARED_CI_WORKFLOW'] = json.dumps({'jobs': {'validate': {'enabled': False, 'plan': None}}})
        self.preflight()
        self.runner.assert_not_called()
        self.scan.assert_called_once()
        reuse.verify_preflight(self.evidence, self.candidate, self.controller, None, [])

    def test_runtime_cannot_start_without_a_preflight_artifact(self):
        with self.assertRaises(ValueError):
            reuse.validate(self.candidate, self.controller, self.evidence, phase='runtime')
        self.native.assert_not_called()
        self.restore.assert_not_called()

    def test_context_owners_and_bootstrap_keep_required_checks_and_attestation(self):
        def workflow(name):
            return json.loads(subprocess.check_output([YQ, '-o=json', '.', str(ROOT / '.github/workflows' / name)], text=True))
        with patch.object(subprocess, 'run', NATIVE_RUN):
            ci = workflow('ci.yml')
            security = workflow('security-audit.yml')
        self.assertNotIn('pull_request', security['on'])
        self.assertNotIn('merge_group', security['on'])
        self.assertEqual(set(security['on']), {'push', 'schedule', 'workflow_dispatch'})
        self.assertEqual(ci['jobs']['preflight']['name'], 'Repository security audit')
        self.assertEqual(ci['jobs']['validate']['needs'], ['classify', 'preflight'])
        self.assertIn('preflight', ci['jobs']['gate']['needs'])
        self.assertEqual(ci['jobs']['gate']['name'], 'CI gate')
        self.assertEqual(ci['jobs']['attest-builds']['needs'], 'validate')
        bootstrap = next(step for step in ci['jobs']['validate']['steps'] if 'bootstrap without reuse certification' in step.get('name', ''))
        self.assertTrue(bootstrap['run'].endswith(' ci:bootstrap-validate'))


if __name__ == '__main__':
    unittest.main()
