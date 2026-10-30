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
from unittest.mock import patch, Mock

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
                            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2',
                            'XO_NIXPKG_TRUSTED_PLAN_NIX': '/nix/store/fixture/bin/xo-nixpkg-candidate-nix',
                            'XO_NIXPKG_PLAN_RUNNER': '/nix/store/fixture/bin/plan-runner',
                            'XO_NIXPKG_HISTORY_SCAN_SOURCE': str(ROOT / 'ci/history-scan.py'),
                            'XO_NIXPKG_SECRET_SCANNER': '/nix/store/fixture/bin/gitleaks',
                            'XO_NIXPKG_SECRET_SCANNER_IDENTITY': '/nix/store/fixture-identity.json',
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

    def export_fixture(self, event='workflow_dispatch'):
        path = self.root / 'event.json'
        path.write_text(json.dumps({'pull_request': {'base': {'sha': 'b' * 40}, 'head': {'repo': {'full_name': reuse.REPOSITORY}}}, 'merge_group': {'base_sha': 'b' * 40}}))
        os.environ.update(GITHUB_EVENT_NAME=event, GITHUB_REPOSITORY=reuse.REPOSITORY,
                          GITHUB_REF='refs/heads/main', GITHUB_EVENT_PATH=str(path), XO_NIXPKG_BUILD_JOBS='2')
        self.output = self.root / 'github-output'
        os.environ['GITHUB_OUTPUT'] = str(self.output)
        self.item = {'storePath': '/nix/store/' + '1' * 32 + '-xo', 'derivation': '/nix/store/' + '2' * 32 + '-xo.drv'}
        self.nar_hash = 'sha256-' + 'A' * 43 + '='
        self.identify = self.patch(patch.object(reuse, 'identity', return_value=self.item))
        self.native.side_effect = lambda env, *args: json.dumps({self.item['storePath']: {'narHash': self.nar_hash}}) if args[0] == 'path-info' else ''
        def build(arguments, **kwargs):
            self.run_plan(arguments, **kwargs)
            self.assertNotIn('XO_NIXPKG_EXPORT_REUSE_PAYLOAD', kwargs['env'])
            target = Path(arguments[arguments.index('--manifest') + 1])
            data = json.loads(target.read_text())
            for result in data['results']:
                if result['name'] == 'xo-latest':
                    result['outputs'] = [self.item['storePath']]
            reuse.write_json(target, data)
        self.runner.side_effect = build
        def export(directory, roots):
            self.assertEqual(roots, [{'storePath': self.item['storePath'], 'narHash': self.nar_hash}])
            directory.mkdir()
            (directory / 'distribution-cache.tar.part-000').write_bytes(b'data')
            return {'schema': 1, 'archiveSize': 4, 'archiveSha256': 'd' * 64,
                    'parts': {'distribution-cache.tar.part-000': {'size': 4, 'sha256': 'd' * 64}}}
        self.exporter = Mock(side_effect=export)
        self.patch(patch.object(reuse, 'transport', return_value=Mock(export=self.exporter)))

    def test_introduced_scan_is_event_bound_and_receipt_identifies_scope(self):
        self.export_fixture('pull_request')
        self.preflight()
        self.assertEqual(self.scan.call_args.args[0][-6:],
                         ['--mode', 'introduced', '--base-sha', 'b' * 40, '--head-sha', 'a' * 40])
        binding = json.loads((self.evidence / 'preflight-binding.json').read_text())
        self.assertEqual(binding['secretScanScope'],
                         {'mode': 'introduced', 'base': 'b' * 40, 'head': 'a' * 40})
        os.environ['GITHUB_EVENT_NAME'] = 'workflow_dispatch'
        with self.assertRaises(ValueError):
            reuse.verify_preflight(self.evidence, self.candidate, self.controller, self.plan, [self.cheap])

    def test_introduced_scan_rejects_wrong_base_before_scanner(self):
        self.export_fixture('pull_request')
        Path(os.environ['GITHUB_EVENT_PATH']).write_text(json.dumps(
            {'pull_request': {'base': {'sha': 'c' * 40}}}))
        with self.assertRaises(ValueError):
            self.preflight()
        self.scan.assert_not_called()

    def test_all_import_export_combinations_keep_validation_and_output_identities(self):
        self.export_fixture()
        identities = []
        for imports in ('true', 'false'):
            for exports in ('true', 'false'):
                with self.subTest(imports=imports, exports=exports):
                    os.environ.update(XO_NIXPKG_REUSE_BUILDS=imports, XO_NIXPKG_EXPORT_REUSE_PAYLOAD=exports)
                    self.evidence = self.root / ('evidence-' + imports + '-' + exports)
                    self.runner.reset_mock()
                    self.identify.reset_mock()
                    self.restore.reset_mock()
                    self.exporter.reset_mock()
                    self.preflight()
                    reuse.validate(self.candidate, self.controller, self.evidence, phase='runtime', preflight=self.evidence)
                    self.assertEqual(self.runner.call_count, 2)
                    self.assertEqual(self.runner.call_args.args[0][-1], '2')
                    self.restore.assert_called_once()  # Existing restore contract owns the independent import switch.
                    self.identify.assert_called_once()
                    self.assertEqual(self.exporter.call_count, int(exports == 'true'))
                    self.assertEqual((self.evidence / 'reuse-receipt/receipt.json').exists(), exports == 'true')
                    self.assertEqual((self.evidence / 'reuse-payload').exists(), exports == 'true')
                    profile = json.loads((self.evidence / 'reuse-transport.json').read_text())
                    self.assertEqual(profile['reason'], 'exported' if exports == 'true' else 'disabled')
                    self.assertEqual(profile['payloadBytes'], 4 if exports == 'true' else 0)
                    self.assertIsNone(profile['uploadedBytes'])
                    self.assertIsNone(profile['uploadSeconds'])
                    self.assertIsNone(profile['wireBytes'])
                    identities.append(profile['outputs'])
                    self.assertTrue(self.output.read_text().endswith('cache_eligible=' + exports + '\n'))
        self.assertTrue(all(item == identities[0] for item in identities))

    def test_default_exports_for_existing_eligible_events(self):
        for event in ('pull_request', 'merge_group', 'workflow_dispatch'):
            with self.subTest(event=event):
                self.export_fixture(event)
                self.evidence = self.root / event
                self.preflight()
                reuse.validate(self.candidate, self.controller, self.evidence, phase='runtime', preflight=self.evidence)
                self.exporter.assert_called_once()
                receipt = json.loads((self.evidence / 'reuse-receipt/receipt.json').read_text())
                self.assertEqual(receipt['schema'], 1)
                self.assertEqual(receipt['event'], event)
                self.assertEqual(receipt['outputs']['xo-latest']['storePath'], self.item['storePath'])

    def test_disabled_export_still_rejects_wrong_source_and_output_identity(self):
        self.export_fixture()
        os.environ['XO_NIXPKG_EXPORT_REUSE_PAYLOAD'] = 'false'
        self.preflight()
        for failure in ('source', 'output'):
            with self.subTest(failure=failure):
                if failure == 'source':
                    # Keep verified preflight binding intact; mutate only the later source-binding read.
                    original_git = self.git
                    count = [0]
                    def changed(root, *arguments):
                        if root == self.candidate and arguments == ('rev-parse', 'HEAD'):
                            count[0] += 1
                            return ('a' if count[0] == 1 else 'e') * 40
                        return original_git(root, *arguments)
                    with patch.object(reuse, 'git', side_effect=changed), self.assertRaisesRegex(ValueError, 'Built checkout differs'):
                        reuse.validate(self.candidate, self.controller, self.evidence, phase='runtime', preflight=self.evidence)
                else:
                    with patch.object(reuse, 'identity', return_value=dict(self.item, storePath='/nix/store/' + '3' * 32 + '-other')), self.assertRaisesRegex(ValueError, 'Built/evaluated output mismatch'):
                        reuse.validate(self.candidate, self.controller, self.evidence, phase='runtime', preflight=self.evidence)
                self.exporter.assert_not_called()
                self.assertFalse((self.evidence / 'reuse-receipt/receipt.json').exists())

    def test_invalid_export_boolean_fails_before_validation(self):
        for setting in ('', 'TRUE', 'False', '1', 'yes'):
            with self.subTest(setting=setting), patch.dict(os.environ, {'XO_NIXPKG_EXPORT_REUSE_PAYLOAD': setting}), self.assertRaisesRegex(ValueError, 'must be true or false'):
                self.preflight()
        self.runner.assert_not_called()
        self.native.assert_not_called()

    def test_audit_only_still_requires_verified_preflight(self):
        self.export_fixture()
        os.environ.update(XO_NIXPKG_REUSE_BUILDS='false', XO_NIXPKG_EXPORT_REUSE_PAYLOAD='false')
        with self.assertRaises(ValueError):
            reuse.validate(self.candidate, self.controller, self.evidence, phase='runtime')
        self.runner.assert_not_called()
        self.exporter.assert_not_called()
        self.identify.assert_not_called()

    def test_export_failure_never_marks_cache_eligible(self):
        self.export_fixture()
        self.preflight()
        self.exporter.side_effect = subprocess.CalledProcessError(17, ['nix', 'copy'])
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            reuse.validate(self.candidate, self.controller, self.evidence, phase='runtime', preflight=self.evidence)
        self.assertEqual(failure.exception.returncode, 17)
        profile = json.loads((self.evidence / 'reuse-transport.json').read_text())
        self.assertEqual(profile['reason'], 'export-failed')
        self.assertIsNone(profile['archiveBytes'])
        self.assertIsNone(profile['payloadBytes'])
        self.assertTrue(self.output.read_text().endswith('cache_eligible=false\n'))
        self.assertFalse((self.evidence / 'reuse-receipt/receipt.json').exists())

    def test_shared_checks_and_history_precede_runtime_without_duplicate_selected_targets(self):
        self.preflight()
        self.scan.assert_called_once()
        self.assertEqual(self.scan.call_args.args[0], [reuse.sys.executable, str(ROOT / 'ci/history-scan.py'), '--mode', 'full'])
        self.assertEqual(self.scan.call_args.kwargs['timeout'], 1260)
        self.assertEqual(self.scan.call_args.kwargs['env']['PYTHONPATH'], str(Path(reuse.operations.__file__).parent))
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
        self.assertEqual(ci['jobs']['attest-builds']['if'], "needs.validate.outputs.cache_eligible == 'true'")
        self.assertEqual(ci['on']['workflow_dispatch']['inputs']['export_reuse_payload']['default'], True)
        self.assertEqual(ci['on']['workflow_dispatch']['inputs']['export_reuse_payload']['type'], 'boolean')
        for name in ('preflight', 'validate'):
            expression = ci['jobs'][name]['env']['XO_NIXPKG_EXPORT_REUSE_PAYLOAD']
            self.assertIn("github.event_name != 'workflow_dispatch' || inputs.export_reuse_payload", expression)
            self.assertNotIn('reuse_builds', expression)
        uploads = [step for step in ci['jobs']['validate']['steps'] if step.get('name') in
                   ('Retain exact sandboxed output bytes', 'Retain independently signable output receipt')]
        self.assertEqual(len(uploads), 2)
        self.assertTrue(all(step['if'] == "steps.trusted.outputs.cache_eligible == 'true'" for step in uploads))
        bootstrap = next(step for step in ci['jobs']['validate']['steps'] if 'bootstrap without reuse certification' in step.get('name', ''))
        self.assertTrue(bootstrap['run'].endswith(' ci:bootstrap-validate'))


if __name__ == '__main__':
    unittest.main()
