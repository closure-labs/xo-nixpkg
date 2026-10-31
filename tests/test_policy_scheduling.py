"""Authenticated obsolete policy is scheduling debt, never usable evidence."""
import copy
import datetime as dt
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci/decisions'))
import common
import scheduling


class PolicyScheduling(unittest.TestCase):
    def setUp(self):
        self.binding = {'policyId': 'gitleaks-incoming-native-publication-v2', 'policySha256': 'a' * 64}
        self.cfg = {'profiles': ['fixture'], 'repositorySecretPolicy': self.binding}
        now = dt.datetime.now(dt.timezone.utc)
        self.native = {'repositorySecretPolicy': self.binding,
                       'scannedAt': (now - dt.timedelta(hours=1)).isoformat(),
                       'expiresAt': (now + dt.timedelta(hours=1)).isoformat(),
                       'profiles': {'fixture': {'status': 'complete', 'scannerHealth': 'healthy',
                           'scannedAt': now.isoformat(),
                           'database': {'valid': True, 'built': (now - dt.timedelta(hours=2)).isoformat()}}}}
        self.product = {'repositorySecretPolicy': self.binding}

    def classify(self):
        return scheduling.authenticated_policy_observation(Path('/fixture'), self.cfg)

    def test_current_and_valid_old_and_legacy_all_authenticate_first(self):
        for binding, expected in [(self.binding, 'current-policy'),
                                  ({'policyId': 'native-provider-observation-v1', 'policySha256': 'b' * 64},
                                   'awaiting-current-evidence'), (None, 'awaiting-current-evidence')]:
            calls = []
            self.native['repositorySecretPolicy'] = self.product['repositorySecretPolicy'] = binding
            def scan(*args, **kwargs):
                calls.append('producer-and-scan-attestation')
                self.assertIs(kwargs['allow_expired'], True)
                return self.native
            def product(*args, **kwargs):
                calls.append('product-provenance-and-attestation')
                return self.product
            with patch.object(common, 'scans', side_effect=scan), patch.object(common, 'product', side_effect=product):
                self.assertEqual(self.classify()[2], expected)
            self.assertEqual(calls, ['producer-and-scan-attestation', 'product-provenance-and-attestation'])

    def test_authentication_schema_and_api_failure_are_never_wait_results(self):
        for validator in ['scans', 'product']:
            for message in ['malformed proof', 'untrusted signature', 'API 403', 'API 404', 'API 429', 'network unavailable']:
                with patch.object(common, 'scans', return_value=self.native) as scans, \
                     patch.object(common, 'product', return_value=self.product) as product:
                    {'scans': scans, 'product': product}[validator].side_effect = ValueError(message)
                    with self.assertRaises(ValueError):
                        self.classify()

    def test_malformed_or_mismatched_policy_remains_fatal_after_authentication(self):
        for scan_policy, product_policy in [({}, {}),
                ({'policyId': 'legacy', 'policySha256': 'invalid'}, {'policyId': 'legacy', 'policySha256': 'invalid'}),
                (None, self.binding), (self.binding, None)]:
            self.native['repositorySecretPolicy'], self.product['repositorySecretPolicy'] = scan_policy, product_policy
            with patch.object(common, 'scans', return_value=self.native), \
                 patch.object(common, 'product', return_value=self.product):
                with self.assertRaises(ValueError):
                    self.classify()

    def test_incomplete_observations_cannot_be_reclassified_as_old_policy(self):
        self.native.update(repositorySecretPolicy=None, profiles={})
        self.product['repositorySecretPolicy'] = None
        with patch.object(common, 'scans', return_value=self.native), \
             patch.object(common, 'product', return_value=self.product):
            with self.assertRaises(ValueError):
                self.classify()

    def test_awaiting_result_denies_authority(self):
        outcome = scheduling.result('owner/repo', 'a' * 40, 'b' * 40, 1, 1, 'wait', 'obsolete-policy')
        self.assertFalse(outcome['authorityClaim'])
        self.assertEqual(outcome['action'], 'wait')
