"""Native review owns authority; shared validation binds exact qualified bytes."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci/decisions'))
import native_approvals as native
import common


def public_policy_binding():
    # This is public scanner-policy identity, never a credential or secret value.
    return {'policyId': 'fixture-public-scanner-policy', 'policySha256': '0' * 64}


def cfg():
    policy = native.policy(ROOT / native.POLICY)
    policy['repositorySecretPolicy'] = public_policy_binding()
    return policy


def request():
    policy = cfg()
    product = {'schema': 1, 'repository': policy['repository'], 'revision': 'a' * 40,
               'products': {name: {'storePath': '/nix/store/' + 'a' * 32 + '-' + name,
                                    'narHash': 'sha256-' + 'A' * 43 + '='} for name in policy['profiles']},
               'assets': {}, 'roots': {}, 'repositorySecretPolicy': public_policy_binding()}
    return {'schema': 1, 'approvalMode': policy['approvalMode'], 'repository': policy['repository'],
            'sourceRevision': product['revision'], 'qualificationRun': 123, 'qualificationAttempt': 2,
            'purpose': 'rolling', 'environment': 'publication', 'policyHash': common.canonical_hash(policy),
            'product': product, 'productHash': common.canonical_hash(product), 'scansHash': 'b' * 64,
            'findingsHash': 'c' * 64, 'findingCounts': {name: 1 for name in policy['profiles']}, 'authorityClaim': False}


def rules():
    return [{'type': 'deletion'}, {'type': 'non_fast_forward'},
            {'type': 'pull_request', 'parameters': {
                'required_approving_review_count': 1, 'dismiss_stale_reviews_on_push': True,
                'require_code_owner_review': True, 'required_review_thread_resolution': True}},
            {'type': 'merge_queue', 'parameters': {'max_entries_to_merge': 1, 'check_response_timeout_minutes': 300}},
            deepcopy(native.CODEQL_RULE),
            {'type': 'required_status_checks', 'parameters': {'required_status_checks': [
                {'context': name, 'integration_id': 15368} for name in native.CHECKS]}}]


def environment():
    return {'name': 'publication', 'id': 12, 'can_admins_bypass': False,
            'protection_rules': [{'type': 'branch_policy'}],
            'deployment_branch_policy': {'protected_branches': True, 'custom_branch_policies': False}}


class NativeProtection(unittest.TestCase):
    def test_completed_analysis_jobs_do_not_replace_finding_protection(self):
        without = [rule for rule in rules() if rule['type'] != 'code_scanning']
        with self.assertRaisesRegex(ValueError, 'CodeQL finding protection'):
            native.validate_rules(cfg(), without)
        for key, value in [('tool', 'Other scanner'), ('alerts_threshold', 'none'),
                           ('security_alerts_threshold', 'none'), ('security_alerts_threshold', 'critical')]:
            current = rules()
            current[4]['parameters']['code_scanning_tools'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'CodeQL finding protection'):
                native.validate_rules(cfg(), current)
        current = rules()
        current[4]['parameters']['code_scanning_tools'][0].update(
            alerts_threshold='all', security_alerts_threshold='medium_or_higher')
        native.validate_rules(cfg(), current)

    def test_native_reviews_and_owned_actions_checks_are_required(self):
        native.validate_rules(cfg(), rules())
        mutations = [(2, 'required_approving_review_count', 0),
                     (2, 'dismiss_stale_reviews_on_push', False), (2, 'require_code_owner_review', False),
                     (2, 'required_review_thread_resolution', False), (3, 'max_entries_to_merge', 2),
                     (3, 'check_response_timeout_minutes', 180), (3, 'check_response_timeout_minutes', True)]
        for index, key, value in mutations:
            rows = rules()
            rows[index]['parameters'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                native.validate_rules(cfg(), rows)
        rows = rules()
        rows[-1]['parameters']['required_status_checks'][0]['integration_id'] = 999
        with self.assertRaisesRegex(ValueError, 'integration identity'):
            native.validate_rules(cfg(), rows)

    def test_environment_restricts_branches_without_a_second_review(self):
        self.assertEqual(native.validate_environment(cfg(), environment()), 12)
        for key, value in [('can_admins_bypass', True), ('deployment_branch_policy', None),
                           ('protection_rules', [{'type': 'required_reviewers'}])]:
            current = environment()
            current[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                native.validate_environment(cfg(), current)

    def test_live_protection_does_not_accept_ruleset_bypasses(self):
        def api(path):
            if path.endswith('/rules/branches/main'):
                return rules()
            if '/rulesets/' in path:
                return {'enforcement': 'active', 'bypass_actors': [{'actor_id': 1}]}
            return environment()
        with self.assertRaisesRegex(ValueError, 'bypass actors'):
            native.protections(cfg(), api)

    def test_observer_is_read_only_and_limited_to_protection_endpoints(self):
        with patch.dict(os.environ, {'NATIVE_SECRET_OBSERVER_TOKEN': 'fixture', 'GH_TOKEN': 'metadata'}), \
                patch.object(native.subprocess, 'run') as execute:
            execute.return_value.stdout = '{}'
            native.protection_api('repos/' + native.REPOSITORY + '/environments/publication')
            self.assertEqual(execute.call_args.kwargs['env']['GH_TOKEN'], 'fixture')
            self.assertEqual(execute.call_args.args[0][:4], ['gh', 'api', '--method', 'GET'])
            with self.assertRaisesRegex(ValueError, 'Unexpected'):
                native.protection_api('repos/' + native.REPOSITORY + '/pulls/1/reviews')
            self.assertEqual(os.environ['GH_TOKEN'], 'metadata')


class ReleaseRequest(unittest.TestCase):
    def test_request_binds_complete_exact_product_and_current_policy(self):
        self.assertEqual(native.validate_request(cfg(), request()), request())
        for key, value in [('schema', True), ('authorityClaim', True), ('qualificationRun', True),
                           ('qualificationAttempt', 0), ('purpose', 'anything'), ('scansHash', 'invalid'),
                           ('policyHash', 'f' * 64), ('findingCounts', {})]:
            current = request()
            current[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                native.validate_request(cfg(), current)
        current = request()
        current['product']['revision'] = 'd' * 40
        with self.assertRaisesRegex(ValueError, 'product identity'):
            native.validate_request(cfg(), current)

    def test_any_changed_reviewed_binding_requires_a_new_release_review(self):
        original = request()
        native.validate_plan(original, deepcopy(original))
        for key in ('sourceRevision', 'qualificationRun', 'qualificationAttempt', 'purpose',
                    'product', 'productHash', 'scansHash', 'findingsHash', 'findingCounts', 'policyHash'):
            changed = deepcopy(original)
            changed[key] = 'changed'
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'reviewed plan'):
                native.validate_plan(original, changed)

    def test_request_rejects_links_duplicate_keys_and_unbounded_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'request.json'
            path.write_text(json.dumps(request()))
            self.assertEqual(native.read_request(cfg(), path), request())
            link = Path(temporary) / 'link'
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, 'regular file'):
                native.read_request(cfg(), link)
            path.write_text('{"schema":1,"schema":1}')
            with self.assertRaises(ValueError):
                native.read_request(cfg(), path)
            path.write_text(' ' * 65537)
            with self.assertRaisesRegex(ValueError, 'bounded'):
                native.read_request(cfg(), path)

    def test_new_approved_target_invalidates_old_publication(self):
        current = request()
        changed = deepcopy(current)
        changed['purpose'] = 'release'
        with patch.object(common, 'main_revision', return_value='a' * 40), \
                patch.object(native.github, 'document_at', return_value=changed):
            with self.assertRaisesRegex(ValueError, 'different approved release'):
                native.current_request(cfg(), current)

    def test_repository_request_is_valid_when_present(self):
        policy = native.policy(ROOT / native.POLICY)
        path = ROOT / policy['releaseRequestPath']
        if path.exists():
            native.read_request(policy, path)

    def test_qualification_never_rebuilds_for_a_release_request_alone(self):
        import yaml
        workflow = yaml.safe_load((ROOT / '.github/workflows/qualification.yml').read_text())
        events = workflow.get('on', workflow.get(True))
        self.assertIn('.github/release-request.json', events['push']['paths-ignore'])
        publishing = yaml.safe_load((ROOT / '.github/workflows/publish.yml').read_text())
        events = publishing.get('on', publishing.get(True))
        self.assertEqual(events['push']['paths'], ['.github/release-request.json'])
        self.assertNotIn('workflow_run', events)

    def test_daily_refresh_and_monthly_transport_renewal_select_one_operation(self):
        from types import SimpleNamespace
        import yaml
        value = yaml.load((ROOT / '.github/workflows/qualification.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(value['on']['schedule'], [{'cron': '17 5 2-31 * *'}, {'cron': '17 5 1 * *'}])
        steps = value['jobs']['qualify']['steps']
        refresh = next(step for step in steps if step['name'] == 'Refresh exact retained product with current trusted scanner')
        build = next(step for step in steps if step['name'] == 'Build complete runtime inventories and scan fresh databases')
        cases = [('schedule', '17 5 2-31 * *', '', True), ('schedule', '17 5 1 * *', '', False),
                 ('workflow_dispatch', '', '', False), ('workflow_dispatch', '', '123', True), ('push', '', '', False)]
        for event, cron, retained, expected_refresh in cases:
            scope = {'github': SimpleNamespace(event_name=event, event=SimpleNamespace(schedule=cron)),
                     'inputs': SimpleNamespace(qualification_run=retained)}
            results = [bool(eval(step['if'].replace('&&', ' and ').replace('||', ' or '),
                                 {'__builtins__': {}}, scope)) for step in (refresh, build)]
            self.assertEqual(results, [expected_refresh, not expected_refresh])

    def test_workflow_tools_are_buildable_packages_and_keep_their_own_git_dependency(self):
        source = (ROOT / 'flake.nix').read_text().split('      packages = ', 1)[1].split('      devShells = ', 1)[0]
        for name, attr in [('publication-plan', 'publicationPlan'), ('release-proposal', 'releaseProposal'),
                           ('fetch-evidence', 'fetchEvidence'), ('publication-controller', 'publicationController')]:
            self.assertIn(name + ' = applications.' + attr + ';', source)
        planner = (ROOT / 'nix/applications.nix').read_text().split('  publicationPlan = ', 1)[1].split('  releaseProposal = ', 1)[0]
        self.assertIn('      git\n', planner)


class NativePublisher(unittest.TestCase):
    def setUp(self):
        self.env = {'GITHUB_ACTIONS': 'true', 'GITHUB_JOB': 'publish', 'GITHUB_REPOSITORY': native.REPOSITORY,
                    'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': 'd' * 40,
                    'GITHUB_WORKFLOW_REF': native.REPOSITORY + '/.github/workflows/publish.yml@refs/heads/main',
                    'GITHUB_RUN_ID': '789', 'GITHUB_RUN_ATTEMPT': '2'}
        self.run = {'id': 789, 'run_attempt': 2, 'head_sha': 'd' * 40, 'head_branch': 'main',
                    'event': 'push', 'path': '.github/workflows/publish.yml', 'status': 'in_progress',
                    'repository': {'full_name': native.REPOSITORY}}
        self.job = {'name': 'Publish reviewed immutable product', 'head_sha': 'd' * 40, 'status': 'in_progress'}

    def api(self, endpoint):
        if '/jobs?' in endpoint:
            return {'total_count': 1, 'jobs': [self.job]}
        self.assertNotIn('/reviews', endpoint)
        return self.run

    def test_real_native_publisher_needs_no_custom_review_evaluation(self):
        self.assertEqual(native.publication_context(cfg(), self.api, self.env), {'runId': 789, 'runAttempt': 2})

    def test_wrong_branch_job_workflow_or_rerun_cannot_publish(self):
        for key, value in [('GITHUB_REF', 'refs/heads/topic'), ('GITHUB_JOB', 'plan'),
                           ('GITHUB_RUN_ATTEMPT', '1'), ('GITHUB_WORKFLOW_REF', 'other/repo/workflow')]:
            env = dict(self.env, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                native.publication_context(cfg(), self.api, env)
        self.job['status'] = 'queued'
        with self.assertRaisesRegex(ValueError, 'has not started'):
            native.publication_context(cfg(), self.api, self.env)


class QualifiedPlanner(unittest.TestCase):
    def setUp(self):
        self.cfg = cfg()
        self.product = request()['product']
        self.scan = {'schema': 1, 'revision': 'a' * 40, 'repositorySecretPolicy': public_policy_binding(),
                     'producer': {'runId': 123, 'runAttempt': 2},
                     'profiles': {name: {'status': 'complete', 'scannerHealth': 'healthy', 'observations': []}
                                  for name in self.cfg['profiles']}}
        self.latest = {'id': 123, 'run_attempt': 2, 'status': 'completed', 'conclusion': 'success'}
        for name, value in [('scans', self.scan), ('product', self.product), ('main_revision', 'd' * 40)]:
            setting = patch.object(common, name, return_value=value)
            setting.start()
            self.addCleanup(setting.stop)

    def api(self, endpoint):
        return {'status': 'ahead'} if '/compare/' in endpoint else self.latest

    def test_planning_does_not_select_or_authenticate_a_legacy_decision(self):
        with patch.object(common, 'ledger', side_effect=AssertionError('legacy ledger')):
            value = native.plan(self.cfg, Path('fixture'), 'rolling', 123, None, self.api)
        self.assertEqual(value['qualificationAttempt'], 2)
        self.assertFalse(value['authorityClaim'])
        self.assertEqual(value['product'], self.product)
        native.validate_request(self.cfg, value)

    def test_changed_attempt_or_incomplete_profile_cannot_be_planned(self):
        for attempt in (1, True, 0):
            with self.subTest(attempt=attempt), self.assertRaises(ValueError):
                native.plan(self.cfg, Path('fixture'), 'rolling', 123, attempt, self.api)
        self.latest['run_attempt'] = 3
        with self.assertRaisesRegex(ValueError, 'attempt changed'):
            native.plan(self.cfg, Path('fixture'), 'rolling', 123, 2, self.api)
        self.latest['run_attempt'] = 2
        self.scan['profiles'].pop('libvhdi')
        with self.assertRaisesRegex(ValueError, 'every configured profile'):
            native.plan(self.cfg, Path('fixture'), 'rolling', 123, 2, self.api)

    def test_new_scan_bytes_require_review_even_with_identical_empty_findings(self):
        first = native.plan(self.cfg, Path('fixture'), 'rolling', 123, 2, self.api)
        self.scan['scannedAt'] = 'new authenticated observation'
        second = native.plan(self.cfg, Path('fixture'), 'rolling', 123, 2, self.api)
        self.assertEqual(first['productHash'], second['productHash'])
        self.assertEqual(first['findingsHash'], second['findingsHash'])
        with self.assertRaisesRegex(ValueError, 'reviewed plan'):
            native.validate_plan(first, second)

    def test_cli_resolves_an_unspecified_attempt_from_authenticated_evidence(self):
        import contextlib
        import io
        spec = importlib.util.spec_from_file_location('native_plan_cli', ROOT / 'ci/publication-plan.py')
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / 'evidence'
            evidence.mkdir()
            (evidence / 'scans.json').write_text(json.dumps(self.scan))
            output = Path(temporary) / 'request.json'
            with patch.dict(os.environ, {'XO_NIXPKG_EVIDENCE': str(evidence), 'QUALIFICATION_RUN': '123',
                                         'QUALIFICATION_ATTEMPT': '', 'XO_NIXPKG_PUBLICATION_PURPOSE': 'rolling',
                                         'GITHUB_STEP_SUMMARY': ''}), \
                    patch.object(sys, 'argv', ['planner', 'plan', '--output', str(output)]), \
                    patch.object(cli.native, 'policy', return_value=self.cfg), patch.object(cli.native, 'protections'), \
                    patch.object(cli, 'controller', return_value='d' * 40), \
                    patch.object(cli.native.github, 'github_api', side_effect=self.api), \
                    patch.object(cli.native, 'publication_context', side_effect=AssertionError('publisher context')), \
                    contextlib.redirect_stdout(io.StringIO()):
                cli.main()
            self.assertEqual(json.loads(output.read_text())['qualificationAttempt'], 2)
            self.assertTrue((Path(temporary) / 'publication-review.json').is_file())


class NativeReleaseProposal(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('native_proposal_fixture', ROOT / 'ci/propose-release.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.calls, self.documents, self.old = [], {}, 'b' * 40
        self.head, self.move = self.old, False
        self.owner = 'cl-decider[bot]'

    def api(self, endpoint, body=None, method=None, missing=False):
        self.calls.append((endpoint, body, method))
        if endpoint.endswith('/git/ref/heads/main'):
            return {'object': {'sha': 'a' * 40}}
        if '/git/ref/heads/automation/release-' in endpoint:
            return {'object': {'sha': self.head}} if self.head else None
        if '/git/commits/' in endpoint:
            return {'tree': {'sha': 'c' * 40}}
        if endpoint.endswith('/git/trees'):
            self.assertEqual(len(body['tree']), 1)
            self.assertEqual(body['tree'][0]['path'], '.github/release-request.json')
            return {'sha': 'c' * 40}
        if endpoint.endswith('/git/commits'):
            self.assertEqual(body['parents'], [self.old, 'a' * 40] if self.old else ['a' * 40])
            return {'sha': 'd' * 40}
        if '/git/refs' in endpoint:
            self.assertIs(body.get('force', False), False)
            self.head = 'f' * 40 if self.move else body['sha']
            return {}
        if '/pulls?' in endpoint:
            return [] if self.owner == 'cl-decider[bot]' else [{'user': {'login': self.owner}, 'number': 7}]
        if endpoint.endswith('/pulls'):
            self.assertIn('publication-review', body['body'])
            return {'number': 7, 'user': {'login': 'cl-decider[bot]'}, 'html_url': 'https://github.com/example/pull/7'}
        self.fail('Unexpected proposal API endpoint: ' + endpoint)

    def propose(self):
        with patch.object(self.module, 'document', side_effect=lambda call, prefix, path, sha: self.documents.get(sha)):
            return self.module.propose(cfg(), request(), 456, self.api)

    def test_updated_request_is_one_file_and_uses_a_nonforcing_branch_update(self):
        self.assertEqual(self.propose()['head'], 'd' * 40)
        self.assertTrue(any(method == 'PATCH' and '/git/refs/' in endpoint for endpoint, _, method in self.calls))
        self.assertFalse(any('/reviews' in endpoint or '/check-runs' in endpoint for endpoint, _, _ in self.calls))

    def test_identical_retry_preserves_the_reviewed_head(self):
        self.documents[self.old] = request()
        self.assertEqual(self.propose()['head'], self.old)
        self.assertFalse(any('/git/refs' in endpoint for endpoint, _, _ in self.calls))

    def test_already_approved_request_does_not_create_an_empty_release_pr(self):
        self.documents['a' * 40] = request()
        self.assertEqual(self.propose()['status'], 'already-approved')
        self.assertTrue(all(body is None for _, body, _ in self.calls))

    def test_branch_movement_prevents_requesting_review(self):
        self.move = True
        with self.assertRaisesRegex(ValueError, 'branch moved'):
            self.propose()
        self.assertFalse(any('/pulls' in endpoint and body is not None for endpoint, body, _ in self.calls))

    def test_an_unowned_open_release_pr_is_rejected_before_any_write(self):
        self.owner = 'human-maintainer'
        with self.assertRaisesRegex(ValueError, 'automation author'):
            self.propose()
        self.assertTrue(all(body is None for _, body, _ in self.calls))


class Cutover(unittest.TestCase):
    def test_prepare_adds_codeql_and_preserves_stricter_thresholds_and_other_tools(self):
        spec = importlib.util.spec_from_file_location('native_cutover_codeql', ROOT / 'ci/configure-native-approvals.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        value = {'name': 'main', 'target': 'branch', 'enforcement': 'active', 'conditions': {},
                 'bypass_actors': [], 'rules': [rule for rule in rules() if rule['type'] != 'code_scanning']}
        prepared = module.prepare_rules(value)
        scanner = next(rule for rule in prepared['rules'] if rule['type'] == 'code_scanning')
        self.assertEqual(scanner['parameters']['code_scanning_tools'], [
            {'tool': 'CodeQL', 'alerts_threshold': 'errors', 'security_alerts_threshold': 'high_or_higher'}])
        self.assertFalse(any(rule['type'] == 'code_scanning' for rule in value['rules']))
        tool = scanner['parameters']['code_scanning_tools'][0]
        tool.update(alerts_threshold='all', security_alerts_threshold='medium_or_higher')
        other = {'tool': 'Other scanner', 'alerts_threshold': 'all', 'security_alerts_threshold': 'all'}
        scanner['parameters']['code_scanning_tools'].append(other)
        self.assertEqual(module.prepare_rules(prepared)['rules'], prepared['rules'])
        scanner['parameters']['code_scanning_tools'].pop(0)
        restored = module.prepare_rules(prepared)
        tools = next(rule for rule in restored['rules'] if rule['type'] == 'code_scanning')['parameters']['code_scanning_tools']
        self.assertEqual(tools[0], other)
        self.assertEqual(tools[1]['tool'], 'CodeQL')
        tools[1].update(alerts_threshold='none', security_alerts_threshold='critical')
        tightened = module.prepare_rules(restored)
        native.validate_rules(cfg(), tightened['rules'])

    def test_prepare_preserves_legacy_gate_until_reviewed_source_is_activated(self):
        spec = importlib.util.spec_from_file_location('native_cutover', ROOT / 'ci/configure-native-approvals.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        old = {'name': 'main', 'target': 'branch', 'enforcement': 'active', 'conditions': {},
               'bypass_actors': [], 'rules': rules()}
        legacy = {'context': 'Maintainer decision authority', 'integration_id': 5384448}
        old['rules'][-1]['parameters']['required_status_checks'].append(legacy)
        prepared = module.prepare_rules(old)
        self.assertIn(legacy, prepared['rules'][-1]['parameters']['required_status_checks'])
        activated = module.activate_rules(prepared)
        self.assertNotIn(legacy, activated['rules'][-1]['parameters']['required_status_checks'])
        native.validate_rules(cfg(), activated['rules'])
        self.assertEqual(old['bypass_actors'], [])

    def test_check_phase_never_changes_settings_or_writes_a_backup(self):
        spec = importlib.util.spec_from_file_location('native_cutover_check', ROOT / 'ci/configure-native-approvals.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(sys, 'argv', ['cutover', 'check', '--backup-dir', temporary]), \
                patch.object(module.native, 'policy', return_value=cfg()), \
                patch.object(module.native, 'protections'), patch.object(module, 'api', return_value={}) as api:
            module.main()
            self.assertTrue(all(len(call.args) == 1 and not call.kwargs for call in api.call_args_list))
            self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
