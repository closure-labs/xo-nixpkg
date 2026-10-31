# SPDX-License-Identifier: Apache-2.0
"""Safe request counts and fresh-tree policy reuse retain live admission guards."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_product_authority import PublicationAPI
import common
import observability


class AuthorityRequests(unittest.TestCase):
    def test_fresh_complete_tree_binds_policy_without_contents_lookup(self):
        service = PublicationAPI(); calls = []
        def api(endpoint):
            calls.append(endpoint)
            return service(endpoint)
        revision, records, policy = common.ledger(service.policy, api, with_policy=True)
        self.assertEqual(policy, service.policy)
        self.assertTrue(records)
        self.assertTrue(any('/git/ref/heads/main' in p for p in calls))
        self.assertTrue(any('/git/trees/' in p for p in calls))
        self.assertFalse(any('/contents/' in p for p in calls))

    def test_missing_duplicate_nonregular_or_tampered_policy_never_succeeds(self):
        for mode in ['missing', 'duplicate', 'symlink', 'tampered']:
            service = PublicationAPI()
            def api(endpoint):
                value = service(endpoint)
                if '/git/trees/' in endpoint:
                    entries = [e for e in value['tree'] if e['path'] == service.policy['policyPath']]
                    if mode == 'missing': value['tree'].remove(entries[0])
                    elif mode == 'duplicate': value['tree'].append(dict(entries[0]))
                    elif mode == 'symlink': entries[0]['mode'] = '120000'
                if mode == 'tampered' and '/git/blobs/' in endpoint and value['sha'] == service.blob(service.policy)['sha']:
                    value = dict(value, content='e30=')
                return value
            with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {'RUNNER_TEMP': temporary}):
                with self.assertRaises(ValueError):
                    common.ledger(service.policy, api, with_policy=True)

    def test_count_summary_contains_no_endpoint_body_or_authority_claim(self):
        for fail in [False, True]:
            def gate(cfg, scan, product, purpose, api):
                api('private/endpoint?PRIVATE_TOKEN')
                if fail: raise ValueError('PRIVATE_BODY')
                return {'safe': True}
            with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {'RUNNER_TEMP': temporary}), \
                 patch.object(common, '_gate', side_effect=gate):
                if fail:
                    with self.assertRaises(ValueError): common.gate({}, None, api=lambda p: {})
                else: self.assertEqual(common.gate({}, None, api=lambda p: {}), {'safe': True})
                raw = (Path(temporary) / 'authority-api-requests.jsonl').read_text()
                value = json.loads(raw)
                self.assertEqual(value['calls'], 1)
                self.assertEqual(value['status'], 'blocked' if fail else 'passed')
                self.assertFalse(value['authorityClaim'])
                self.assertNotIn('PRIVATE', raw)
                self.assertNotIn('endpoint', raw)

    def test_final_main_change_still_blocks_after_verified_policy_reuse(self):
        cfg = {'enabled': True, 'repository': 'owner/repo'}
        revision = 'a' * 40
        for changed in [False, True]:
            def api(endpoint):
                return {'object': {'sha': 'b' * 40 if changed else revision}} if '/git/ref/' in endpoint else {'status': 'identical'}
            with patch.object(common, 'required_check'), \
                 patch.object(common, 'ledger', side_effect=[(revision, {}), (revision, {}, cfg)]), \
                 patch.object(common, 'scans', return_value={'revision': revision, 'producer': {}}), \
                 patch.object(common, 'admission', return_value={}), patch.object(common, 'active_security'):
                if changed:
                    with self.assertRaisesRegex(ValueError, 'Protected main moved'):
                        common.gate(cfg, None, api=api)
                else: self.assertEqual(common.gate(cfg, None, api=api), {})

    def test_diagnostic_symlink_and_invalid_counts_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {'RUNNER_TEMP': temporary}):
            target = Path(temporary) / 'target'; target.write_text('unchanged')
            (Path(temporary) / 'authority-api-requests.jsonl').symlink_to(target)
            with self.assertRaises(OSError): observability.authority_requests(1, 'passed')
            self.assertEqual(target.read_text(), 'unchanged')
        for count in [-1, True, 100001]:
            with self.assertRaises(ValueError): observability.authority_requests(count, 'passed')
