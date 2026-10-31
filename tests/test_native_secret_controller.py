"""Offline regressions for the authenticated controller and publication boundary."""
import copy
from datetime import datetime, timezone, timedelta
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

M = module('native_controller_test', 'ci/native-secret-controller.py')
GATE = module('native_publication_test', 'ci/audit-freshness.py')
HAS_NATIVE_BOUNDARY = hasattr(GATE, 'native')
MAIN, HEAD = 'a' * 40, 'b' * 40
NOW = datetime(2026, 10, 30, 14, 0, tzinfo=timezone.utc)
POSTURE = {'security_and_analysis': {
    'secret_scanning': {'status': 'enabled'}, 'secret_scanning_push_protection': {'status': 'enabled'},
    'secret_scanning_non_provider_patterns': {'status': 'disabled'},
    'secret_scanning_validity_checks': {'status': 'disabled'}}}


class FixtureAPI:
    def __init__(self):
        self.main = MAIN
        self.posture = copy.deepcopy(POSTURE)
        self.pages = [([], {})]
        self.calls = []
        repo = {'id': M.REPO_ID, 'full_name': M.REPO}
        self.run = {'id': 123, 'repository': repo, 'head_repository': repo,
                    'path': '.github/workflows/ci.yml', 'status': 'completed', 'conclusion': 'success',
                    'event': 'pull_request', 'head_sha': HEAD, 'head_branch': 'fixture'}
        self.pull = {'number': 4, 'state': 'open', 'base': {'ref': 'main', 'repo': repo},
                     'head': {'sha': HEAD, 'ref': 'fixture', 'repo': repo}}

    def get(self, path):
        self.calls.append(path)
        if path == M.PREFIX:
            return copy.deepcopy(self.posture)
        if path.endswith('/git/ref/heads/main'):
            return {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': self.main}}
        if '/actions/runs/' in path:
            return copy.deepcopy(self.run)
        if '/commits/' in path and '/pulls?' in path:
            return [{'number': 4}]
        if path.endswith('/pulls/4'):
            return copy.deepcopy(self.pull)
        if '/compare/' in path:
            return {'status': 'ahead', 'merge_base_commit': {'sha': HEAD}}
        if '/git/ref/heads/gh-readonly-queue/' in path:
            return {'object': {'sha': HEAD}}
        raise AssertionError('unexpected fixture request')

    def request(self, path, method='GET', body=None):
        self.calls.append(path)
        if method == 'POST':
            return 201, {}, {'app': {'id': 15368}}
        number = int(path.rsplit('page=', 1)[1])
        rows, headers = self.pages[number - 1]
        return 200, dict(headers), copy.deepcopy(rows)


def link(page=2, origin='https://api.github.com', hidden='true'):
    return f'<{origin}{M.PREFIX}/secret-scanning/alerts?state=open&hide_secret={hidden}&per_page=100&page={page}>; rel="next"'


class PolicyBindingTests(unittest.TestCase):
    def sources(self):
        return {'XO_NATIVE_SECRET_POLICY_PATH': str(ROOT / 'ci/native-secret-policy.json'),
                'XO_INCOMING_SECRET_WORKFLOW_SOURCE': str(ROOT / '.github/workflows/repository-secret-scan.yml'),
                'XO_GITLEAKS_CONFIG_SOURCE': str(ROOT / '.gitleaks.toml')}

    def test_decision_policy_matches_actual_protected_scanner_files(self):
        with patch.dict(os.environ, self.sources()):
            computed = M.policy_binding()
        configured = json.loads((ROOT / 'ci/decision-policy.json').read_text())['repositorySecretPolicy']
        self.assertEqual(configured, computed,
                         'Scanner/config changes must update the reviewed decision policy binding')

    def test_either_scanner_file_change_invalidates_unchanged_binding(self):
        configured = json.loads((ROOT / 'ci/decision-policy.json').read_text())['repositorySecretPolicy']
        for variable in ('XO_INCOMING_SECRET_WORKFLOW_SOURCE', 'XO_GITLEAKS_CONFIG_SOURCE'):
            sources = self.sources()
            with tempfile.TemporaryDirectory() as temporary:
                changed = Path(temporary) / 'changed-source'
                changed.write_bytes(Path(sources[variable]).read_bytes() + b'\n# changed scanner contract\n')
                sources[variable] = str(changed)
                with patch.dict(os.environ, sources):
                    self.assertNotEqual(M.policy_binding(), configured)
                    with self.assertRaisesRegex(M.Blocked, 'old-policy-qualification'):
                        M.validate_product_policy({'repositorySecretPolicy': configured},
                                                  {'repositorySecretPolicy': configured})

    def test_previous_config_binding_still_cannot_qualify(self):
        previous = {'policyId': 'gitleaks-incoming-native-publication-v2',
                    'policySha256': 'edfc59daaf284da183a59049b2fd2d0232471cb1780d16d9f117edb7bd8e98f3'}
        with patch.dict(os.environ, self.sources()), self.assertRaisesRegex(M.Blocked, 'old-policy-qualification'):
            M.validate_product_policy({'repositorySecretPolicy': previous}, {'repositorySecretPolicy': previous})


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.api = FixtureAPI()

    def test_zero_hidden_alerts_are_observation_not_completion(self):
        selected = M.target(self.api, None, MAIN)
        r = M.observe(self.api, MAIN, selected, now=lambda: NOW)
        self.assertEqual(r['openAlertCount'], 0)
        self.assertIs(r['exactCommitScanCompletionClaim'], False)
        self.assertIs(r['fullHistoryCompletionClaim'], False)

    def test_complete_pagination_is_consumed(self):
        self.api.pages = [([], {'Link': link()}), ([], {})]
        pages = M.alert_pass(self.api)
        self.assertEqual(len(pages), 2)
        self.assertFalse(pages[-1]['hasNext'])

    def test_cycles_origin_and_hidden_downgrades_fail(self):
        for value in [link(1), link(3), link(origin='https://attacker.invalid'), link(hidden='false')]:
            with self.subTest(value=value), self.assertRaises(M.Blocked):
                M.next_page({'Link': value}, 2)

    def test_duplicate_next_relation_or_query_rejected(self):
        for value in [link() + ', ' + link(), link().replace('page=2', 'page=2&page=2')]:
            with self.assertRaises(M.Blocked):
                M.next_page({'Link': value}, 2)

    def test_cap_exhaustion_never_success(self):
        self.api.pages = [([], {'Link': link(n + 1)}) for n in range(1, 21)]
        with self.assertRaisesRegex(M.Blocked, 'pagination-bound'):
            M.alert_pass(self.api)

    def test_schema_and_hidden_payload_fail_without_echo(self):
        self.api.pages = [([{'number': 1, 'state': 'open', 'secret': 'PRIVATE_TOKEN'}], {})]
        with self.assertRaises(M.Blocked) as caught:
            M.alert_pass(self.api)
        self.assertNotIn('PRIVATE_TOKEN', str(caught.exception))

    def test_trusted_run_to_exact_open_repository_pull(self):
        selected = M.target(self.api, 123, MAIN)
        self.assertEqual(selected, {'sha': HEAD, 'kind': 'pull_request', 'run': 123, 'pull': 4})

    def test_candidate_event_foreign_repository_and_path_spoofs_rejected(self):
        for field, value in [('repository', {'id': 1, 'full_name': M.REPO}),
                             ('head_repository', {'id': 1, 'full_name': 'foreign/repo'}),
                             ('event', 'pull_request_target'), ('path', '.github/workflows/evil.yml')]:
            self.api = FixtureAPI(); self.api.run[field] = value
            with self.assertRaises(M.Blocked):
                M.target(self.api, 123, MAIN)

    def test_foreign_pull_and_head_race_rejected(self):
        self.api.pull['head']['repo'] = {'id': 9, 'full_name': 'foreign/repo'}
        with self.assertRaises(M.Blocked):
            M.target(self.api, 123, MAIN)
        self.api = FixtureAPI(); self.api.pull['head']['sha'] = 'c' * 40
        with self.assertRaises(M.Blocked):
            M.target(self.api, 123, MAIN)

    def test_merge_group_ref_is_immutable_live_binding(self):
        self.api.run.update(event='merge_group', head_branch='gh-readonly-queue/main/pr-4-abcdef0')
        self.assertEqual(M.target(self.api, 123, MAIN)['sha'], HEAD)

    def test_current_main_change_blocks(self):
        self.api.main = 'c' * 40
        with self.assertRaisesRegex(M.Blocked, 'protected-main-moved'):
            M.target(self.api, 123, MAIN)

    @unittest.skipUnless(HAS_NATIVE_BOUNDARY, 'Stage2 publication/evidence migration not installed in bootstrap')
    def test_publication_reobserves_even_if_saved_receipt_exists(self):
        binding = GATE.native.policy_binding()
        product = {'repository': M.REPO, 'revision': HEAD, 'repositorySecretPolicy': binding}
        scans = {'repositorySecretPolicy': binding, 'savedNativeObservation': {'status': 'observed'}}
        with patch.object(GATE, 'incoming_check', return_value={'head': HEAD}) as incoming:
            GATE.verify(MAIN, product, scans, self.api, now=lambda: NOW)
            first = len(self.api.calls)
            GATE.verify(MAIN, product, scans, self.api, now=lambda: NOW)
            self.assertEqual(incoming.call_count, 4)
        self.assertGreater(len(self.api.calls), first)
        self.assertEqual(sum('/secret-scanning/alerts?' in p for p in self.api.calls), 4)

    @unittest.skipUnless(HAS_NATIVE_BOUNDARY, 'Stage2 publication/evidence migration not installed in bootstrap')
    def test_old_policy_qualification_rejected_before_api(self):
        for binding in [None, {'policyId': 'old-gitleaks-policy', 'policySha256': 'c' * 64}]:
            with self.assertRaises(GATE.native.Blocked):
                GATE.verify(MAIN, {'repository': M.REPO, 'revision': HEAD,
                                  'repositorySecretPolicy': binding}, {'repositorySecretPolicy': binding}, self.api)
        self.assertEqual(self.api.calls, [])

    def test_native_controller_cannot_publish_merge_checks(self):
        self.assertFalse(hasattr(M, 'publish_check'))
        self.assertFalse((ROOT / '.github/workflows/native-secret-observation.yml').exists())

    def test_failed_or_irrelevant_ci_cannot_publish_observation(self):
        for field, values in [('conclusion', ['failure', 'cancelled', 'timed_out', None]),
                              ('status', ['in_progress']), ('event', ['push', 'workflow_dispatch']),
                              ('path', ['.github/workflows/foreign.yml'])]:
            for value in values:
                api = FixtureAPI()
                api.run[field] = value
                with self.assertRaisesRegex(M.Blocked, 'event-run-binding'):
                    M.target(api, 123, MAIN)

    @unittest.skipUnless(HAS_NATIVE_BOUNDARY, 'Stage2 publication wiring not installed in bootstrap')
    def test_both_publication_boundaries_get_separate_observer(self):
        publisher = (ROOT / '.github/workflows/publish.yml').read_text()
        for boundary in ('release:fetch', 'release:resume'):
            step = next(part for part in publisher.split('      - name:') if boundary in part)
            self.assertIn('NATIVE_SECRET_OBSERVER_TOKEN: ${{ steps.native_observer.outputs.token }}', step)
            self.assertIn('GH_TOKEN: ${{ steps.publisher.outputs.token }}', step)
        workflow = (ROOT / '.github/workflows/repository-secret-scan.yml').read_text()
        self.assertIn('name: Repository security audit', workflow)
        self.assertNotIn('DECIDER_KEY', workflow)

    def test_duplicate_json_and_nonfinite_json_rejected(self):
        for raw in [b'{"id":1,"id":2}', b'{"id":NaN}', b'not-json']:
            with self.assertRaises(M.Blocked): M.decode(raw)

    def test_http403_404_429_and_network_errors_are_sanitized(self):
        api = M.API('FAKE_TOKEN_FOR_UNIT_TEST_ONLY')
        path = M.PREFIX + '/secret-scanning/alerts?state=open&hide_secret=true&per_page=100&page=1'
        for code in [403, 404, 429]:
            api.opener.open = Mock(side_effect=urllib.error.HTTPError('private-url', code, 'PRIVATE_RAW_ERROR', {}, io.BytesIO(b'PRIVATE_BODY')))
            with self.assertRaises(M.Blocked) as caught: api.request(path)
            self.assertNotIn('PRIVATE', str(caught.exception))
        api.opener.open = Mock(side_effect=urllib.error.URLError('PRIVATE_TOKEN'))
        with self.assertRaisesRegex(M.Blocked, '^api-network$'): api.request(path)

    def test_redirects_sizes_and_deadlines_are_fail_closed(self):
        api = M.API('FAKE_TOKEN_FOR_UNIT_TEST_ONLY')
        response = Mock(); response.__enter__ = Mock(return_value=response); response.__exit__ = Mock(return_value=False)
        response.geturl.return_value = 'https://attacker.invalid/private'
        api.opener.open = Mock(return_value=response)
        with self.assertRaisesRegex(M.Blocked, 'redirect-rejected'): api.request(M.PREFIX)
        response.geturl.return_value = 'https://api.github.com' + M.PREFIX
        response.read.return_value = b'x' * (M.MAX_BODY + 1)
        with self.assertRaisesRegex(M.Blocked, 'response-size'): api.request(M.PREFIX)
        api = M.API('FAKE', monotonic=Mock(side_effect=[0, 121]))
        with self.assertRaisesRegex(M.Blocked, 'collection-expired'): api.request(M.PREFIX)

    def test_live_policy_file_change_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'policy.json'; p.write_text('{}')
            with patch.dict(os.environ, {'XO_NATIVE_SECRET_POLICY_PATH': str(p)}), self.assertRaisesRegex(M.Blocked, 'policy-changed'):
                M.policy_binding()

    def test_hard_collection_alarm_interrupts_and_restores_handler(self):
        previous = M.signal.getsignal(M.signal.SIGALRM)
        with self.assertRaisesRegex(M.Blocked, 'collection-expired'):
            with M.wall_budget(1):
                M.signal.getsignal(M.signal.SIGALRM)(M.signal.SIGALRM, None)
        self.assertEqual(M.signal.getsignal(M.signal.SIGALRM), previous)
        self.assertEqual(M.signal.getitimer(M.signal.ITIMER_REAL)[0], 0)

    def test_clock_and_settings_change_during_collection_block(self):
        selected = M.target(self.api, None, MAIN)
        times = iter([NOW, NOW + timedelta(seconds=121), NOW + timedelta(seconds=121)])
        with self.assertRaisesRegex(M.Blocked, 'collection-expired'):
            M.observe(self.api, MAIN, selected, now=lambda: next(times))
        original = self.api.get
        count = [0]
        def changed(path):
            result = original(path)
            if path == M.PREFIX:
                count[0] += 1
                if count[0] > 1:
                    result['security_and_analysis']['secret_scanning_validity_checks']['status'] = 'enabled'
            return result
        self.api.get = changed
        with self.assertRaisesRegex(M.Blocked, 'posture-race'):
            M.observe(self.api, MAIN, selected, now=lambda: NOW)

    @unittest.skipUnless(HAS_NATIVE_BOUNDARY, 'Stage2 publication/evidence migration not installed in bootstrap')
    def test_checked_policy_digest_not_saved_receipt_controls_publication(self):
        good = GATE.native.policy_binding()
        product = {'repository': M.REPO, 'revision': HEAD, 'repositorySecretPolicy': good}
        scans = {'repositorySecretPolicy': dict(good, policySha256='c' * 64)}
        with self.assertRaisesRegex(GATE.native.Blocked, 'old-policy-qualification'):
            GATE.verify(MAIN, product, scans, self.api)

    @unittest.skipUnless(HAS_NATIVE_BOUNDARY, 'Stage2 publication/evidence migration not installed in bootstrap')
    def test_no_app_credentials_in_untrusted_ci_and_signer_separation(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertNotIn('DECIDER_KEY', ci)
        self.assertNotIn('NATIVE_SECRET_OBSERVER_TOKEN', ci)
        observer = (ROOT / '.github/workflows/repository-secret-scan.yml').read_text()
        self.assertNotIn('workflow_run:', observer)
        self.assertNotIn('pull_request_target:', observer)
        self.assertNotIn('DECIDER_KEY', observer)
        publisher = (ROOT / '.github/workflows/publish.yml').read_text()
        self.assertIn('permission-secret-scanning-alerts: read', publisher)
        self.assertIn('NATIVE_SECRET_OBSERVER_TOKEN: ${{ steps.native_observer.outputs.token }}', publisher)
        self.assertIn('GH_TOKEN: ${{ steps.publisher.outputs.token }}', publisher)

    def test_original_product_security_provenance_and_superadmin_checks_remain(self):
        scan = (ROOT / 'ci/security-scan.sh').read_text()
        self.assertIn('grype "sbom:$output/inventory.cdx.json"', scan)
        gate = (ROOT / 'ci/publication-gate.sh').read_text()
        self.assertIn('exec xo-nixpkg-decision-publication', gate)
        common = (ROOT / 'ci/decisions/common.py').read_text()
        for expected in ['attest(path, cfg,', 'def admission(', 'required_check(cfg, api)',
                         'Exact immutable product approval required', 'authorize(cfg, release, api)']:
            self.assertIn(expected, common)
        authority = (ROOT / 'ci/decisions/decision_authority.py').read_text()
        self.assertIn('super-admin', authority.lower())


if __name__ == '__main__':
    unittest.main()
