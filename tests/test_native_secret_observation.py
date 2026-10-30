import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_observation', ROOT / 'ci/native-secret-observation.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def page(number=1, rows=None, next_page=False):
    return {'origin': 'https://api.github.com',
            'requestPath': f'/repos/{M.REPOSITORY}/secret-scanning/alerts?state=open&hide_secret=true&per_page=100&page={number}',
            'httpStatus': 200, 'hideSecret': True, 'hasNext': next_page,
            'alerts': [] if rows is None else rows}


def alert(number=1):
    return {'number': number, 'state': 'open', 'created_at': '2026-10-30T14:00:00Z',
            'updated_at': '2026-10-30T14:00:01Z'}


class ObservationContractTests(unittest.TestCase):
    def setUp(self):
        self.posture = {'security_and_analysis': {
            'secret_scanning': {'status': 'enabled'},
            'secret_scanning_push_protection': {'status': 'enabled'},
            'secret_scanning_non_provider_patterns': {'status': 'disabled'},
            'secret_scanning_validity_checks': {'status': 'disabled'}}}
        self.kw = dict(policy=copy.deepcopy(M.POLICY), repository=M.REPOSITORY,
                       candidate_before='a' * 40, candidate_after='a' * 40,
                       main_before='b' * 40, main_after='b' * 40,
                       posture_before=copy.deepcopy(self.posture), posture_after=copy.deepcopy(self.posture),
                       passes=[[page()], [page()]], started_at='2026-10-30T14:00:00Z',
                       completed_at='2026-10-30T14:00:20Z',
                       now=datetime(2026, 10, 30, 14, 1, tzinfo=timezone.utc))

    def reject(self, reason):
        with self.assertRaisesRegex(M.Blocked, '^' + reason + '$'):
            M.propose_receipt(**self.kw)

    def test_observation_explicitly_has_no_audit_or_gate_authority(self):
        r = M.propose_receipt(**self.kw)
        self.assertEqual(r['openAlertCount'], 0)
        self.assertEqual(r['expiresAt'], '2026-10-30T14:05:00Z')
        for key in ['authorityClaim', 'reuseEligible', 'fullHistoryCompletionClaim', 'exactCommitScanCompletionClaim']:
            self.assertIs(r[key], False)
        self.assertEqual(r['activation'], 'protected-main')

    def test_json_policy_matches_contract(self):
        self.assertEqual(json.loads((ROOT / 'ci/native-secret-policy.json').read_text()), M.POLICY)

    def test_old_policy_or_extra_authority_key_rejected(self):
        for value in [dict(M.POLICY, policyId='gitleaks-v2'), dict(M.POLICY, gateEligible=True),
                      dict(M.POLICY, schema=True)]:
            self.kw['policy'] = value
            self.reject('policy-schema-or-version')

    def test_wrong_repository(self):
        self.kw['repository'] = 'other/repo'; self.reject('repository-scope')

    def test_head_and_main_races(self):
        for key in ['candidate_after', 'main_after']:
            with self.subTest(key=key):
                prior = self.kw[key]; self.kw[key] = 'c' * 40
                self.reject('head-race'); self.kw[key] = prior

    def test_malformed_sha(self):
        self.kw['candidate_before'] = 'main'; self.reject('head-schema')

    def test_inaccessible_settings(self):
        self.kw['posture_before'] = {}; self.reject('posture-inaccessible')

    def test_both_required_settings_fail_closed(self):
        for key in M.POLICY['requiredSettings']:
            self.kw['posture_before'] = copy.deepcopy(self.posture)
            self.kw['posture_before']['security_and_analysis'][key]['status'] = 'disabled'
            self.reject('posture-not-enabled')

    def test_optional_disabled_does_not_change_policy(self):
        r = M.propose_receipt(**self.kw)
        self.assertEqual(r['settings']['secret_scanning_non_provider_patterns'], 'disabled')

    def test_posture_race(self):
        self.kw['posture_after']['security_and_analysis']['secret_scanning_validity_checks']['status'] = 'enabled'
        self.reject('posture-race')

    def test_api_statuses_are_errors_not_disabled(self):
        for status in [403, 404, 429, 500, '200', True]:
            self.kw['passes'] = [[dict(page(), httpStatus=status)], [page()]]
            self.reject('api-error')

    def test_hide_secret_required_and_no_raw_fallback(self):
        self.kw['passes'][0][0]['hideSecret'] = False; self.reject('hidden-secret-required')
        self.kw['passes'][0] = [page(rows=[dict(alert(), secret='DO_NOT_SERIALIZE')])]
        self.reject('secret-not-hidden')

    def test_redirect_and_parameter_downgrade_rejected(self):
        for key, value in [('origin', 'https://attacker.invalid'),
                           ('requestPath', '/repos/closure-labs/xo-nixpkg/secret-scanning/alerts?state=open')]:
            self.kw['passes'] = [[dict(page(), **{key: value})], [page()]]
            self.reject('request-scope')

    def test_unfinished_page_and_wrong_order(self):
        self.kw['passes'][0][0]['hasNext'] = True; self.reject('pagination-incomplete')
        self.kw['passes'][0] = [page(number=2)]; self.reject('request-scope')

    def test_page_bound_and_row_bound(self):
        self.kw['passes'][0] = [page()] * 21; self.reject('pagination-bound')
        self.kw['passes'][0] = [page(rows=[alert(i + 1) for i in range(101)])]; self.reject('page-schema')

    def test_duplicate_alerts_across_pages(self):
        self.kw['passes'][0] = [page(rows=[alert()], next_page=True), page(2, [alert()])]
        self.reject('duplicate-alert-id')

    def test_matching_full_passes_required(self):
        self.kw['passes'][0] = [page(rows=[alert()])]; self.reject('alert-inventory-race')

    def test_open_alerts_block_without_payload(self):
        self.kw['passes'] = [[page(rows=[alert()])], [page(rows=[alert()])]]
        self.reject('open-alerts')

    def test_projected_rows_never_include_paths_content_or_unknown_labels(self):
        row = dict(alert(), first_location_detected={'path': 'PRIVATE_PATH', 'content': 'PRIVATE_CONTENT'},
                   secret_type='ARBITRARY_LABEL', resolution_comment='PRIVATE_COMMENT')
        projected = json.dumps(M.inventory([page(rows=[row])]))
        for value in ['PRIVATE_PATH', 'PRIVATE_CONTENT', 'ARBITRARY_LABEL', 'PRIVATE_COMMENT']:
            self.assertNotIn(value, projected)

    def test_malformed_alert_ids_states_and_dates(self):
        for key, value, reason in [('number', True, 'alert-id-schema'), ('state', 'resolved', 'alert-state-race'),
                                   ('created_at', 'not-a-date', 'timestamp-schema')]:
            self.kw['passes'][0] = [page(rows=[dict(alert(), **{key: value})])]
            self.reject(reason)

    def test_stale_observation_and_long_collection(self):
        self.kw['now'] = datetime(2026, 10, 30, 14, 6, tzinfo=timezone.utc)
        self.reject('observation-expired')
        self.kw['completed_at'] = '2026-10-30T14:03:00Z'; self.reject('collection-expired')

    def test_future_or_naive_clock(self):
        self.kw['completed_at'] = '2026-10-30T14:02:00Z'; self.reject('clock-order')
        self.kw['now'] = datetime(2026, 10, 30, 14, 1); self.reject('clock-schema')

    def test_arbitrary_raw_fields_cannot_enter_success_receipt(self):
        self.kw['posture_before']['untrusted'] = 'DO_NOT_SERIALIZE'
        self.kw['posture_after']['untrusted'] = 'DO_NOT_SERIALIZE'
        self.assertNotIn('DO_NOT_SERIALIZE', json.dumps(M.propose_receipt(**self.kw)))

    def test_two_passes_and_terminal_page_are_explicit(self):
        self.kw['passes'] = [[page()]]; self.reject('pass-count')


if __name__ == '__main__':
    unittest.main()
