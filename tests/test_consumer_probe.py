# SPDX-License-Identifier: Apache-2.0
"""Verify the consumer exercises downloaded bytes, signature checks and exact roots."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'ci' if (ROOT / 'ci').is_dir() else ROOT / 'nix/automation'
sys.path.insert(0, str(FOLDER / 'decisions'))
spec = importlib.util.spec_from_file_location('consumer_probe', FOLDER / 'consumer-probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
PATH = '/nix/store/' + 'a' * 32 + '-fixture'
HASH = 'sha256-' + 'A' * 43 + '='
PRODUCT = {'products': {'fixture': {'storePath': PATH, 'narHash': HASH}}}


class ConsumerProbe(unittest.TestCase):
    def execute(self, args, **kwargs):
        self.calls.append(args)
        if self.failure and self.failure in args:
            raise subprocess.CalledProcessError(1, args, stderr='untrusted secret details')
        value = {PATH: {'narHash': self.observed}}
        return subprocess.CompletedProcess(args, 0, json.dumps(value))

    def setUp(self):
        self.calls, self.failure, self.observed = [], None, HASH

    def test_clean_destination_recursive_signature_and_byte_verification(self):
        result = probe.probe(PRODUCT, 'https://cache.example', 'cache-key', self.execute)
        self.assertEqual(result['status'], 'verified')
        realise, verify, metadata = self.calls
        self.assertEqual(realise[:2],['nix-store','--realise'])
        store = realise[realise.index('--store') + 1]
        self.assertTrue(store.startswith('local?root='))
        self.assertFalse(Path(store.removeprefix('local?root=')).exists())
        self.assertEqual(verify[verify.index('--store') + 1], store)
        self.assertIn('--recursive', verify)
        self.assertEqual(verify[verify.index('--sigs-needed') + 1], '1')
        self.assertNotIn('--no-check-sigs', realise)
        self.assertIn(' '.join(('cache-key',*probe.UPSTREAM_KEYS)),realise)
        self.assertIn(' '.join(('https://cache.example',*probe.UPSTREAM_CACHES)),realise)
        self.assertIn(['--option','max-jobs','0'],[realise[i:i+3] for i in range(len(realise)-2)])
        self.assertIn(['--option','builders',''],[realise[i:i+3] for i in range(len(realise)-2)])
        self.assertIn(['--option','fallback','false'],[realise[i:i+3] for i in range(len(realise)-2)])
        self.assertIn(['--option','substitute','true'],[realise[i:i+3] for i in range(len(realise)-2)])
        self.assertEqual(realise[-1], PATH)
        self.assertEqual(metadata[-1], PATH)

    def test_hash_mismatch_blocks(self):
        self.observed = 'sha256-' + 'B' * 43 + '='
        with self.assertRaises(ValueError):
            probe.probe(PRODUCT, 'https://cache.example', 'cache-key', self.execute)

    def test_download_or_signature_failure_blocks(self):
        for operation in ('--realise', 'verify'):
            self.failure = operation
            with self.assertRaises(subprocess.CalledProcessError):
                probe.probe(PRODUCT, 'https://cache.example', 'cache-key', self.execute)

    def test_derivations_and_non_store_paths_are_rejected_before_execution(self):
        for path in [PATH+'.drv','--repair','/tmp/fixture']:
            product={'products':{'fixture':{'storePath':path,'narHash':HASH}}}
            with self.assertRaises(ValueError):probe.probe(product,'https://cache.example','cache-key',self.execute)
        self.assertEqual(self.calls,[])


class ConsumerSelection(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        self.provenance = patch.object(probe.common, 'historical_provenance').start()
        self.addCleanup(patch.stopall)
        probe.common.packets.REFERENCE = __import__('re').compile(
            r'ghcr.io/closure-labs/xo-nixpkg-decisions@sha256:[0-9a-f]{64}')
        self.cfg = {'repository': 'closure-labs/xo-nixpkg',
                    'producerWorkflows': ['.github/workflows/qualification.yml']}

    def proposal(self, run, product=None, disposition='accepted'):
        import copy
        return {'schema': 1, 'kind': 'release-product', 'payload': {
            'product': copy.deepcopy(product or dict(PRODUCT, revision='a' * 40)),
            'disposition': disposition, 'rationale': 'Fixture reviewed.', 'supersedes': [],
            'packet': {'reference': 'ghcr.io/closure-labs/xo-nixpkg-decisions@sha256:' + 'a' * 64,
                       'sha256': 'b' * 64, 'producer': {'runId': run, 'runAttempt': 1}}}}

    def records(self, *values):
        return {probe.common.canonical_hash(p): p for p in values}

    def test_old_ambiguous_product_does_not_select_or_block_current(self):
        old1, old2 = self.proposal(10), self.proposal(11)
        current = self.proposal(20, dict(PRODUCT, revision='b' * 40))
        self.assertEqual(probe.current_product(self.cfg, self.records(old1, old2, current)), current)
        self.provenance.assert_called_once_with(self.cfg, current)

    def test_current_ambiguity_rejection_revocation_and_cycles_fail(self):
        for disposition in ('rejected', 'revoked'):
            with self.subTest(disposition=disposition), self.assertRaisesRegex(ValueError, 'not accepted'):
                probe.current_product(self.cfg, self.records(self.proposal(10),
                    self.proposal(20, dict(PRODUCT, revision='b' * 40), disposition)))
        with self.assertRaisesRegex(ValueError, 'Ambiguous release'):
            probe.current_product(self.cfg, self.records(self.proposal(10), self.proposal(20)))
        a, b = self.proposal(10), self.proposal(20)
        a['payload']['supersedes'] = ['b']
        b['payload']['supersedes'] = ['a']
        with self.assertRaisesRegex(ValueError, 'Cyclic'):
            probe.current_product(self.cfg, {'a': a, 'b': b})

    def test_tied_distinct_products_and_malformed_order_fail(self):
        with self.assertRaisesRegex(ValueError, 'Ambiguous current'):
            probe.current_product(self.cfg, self.records(self.proposal(20),
                self.proposal(20, dict(PRODUCT, revision='b' * 40))))
        for invalid in (True, 0, -1, '20', None):
            with self.subTest(run=invalid), self.assertRaisesRegex(ValueError, 'ordering'):
                probe.current_product(self.cfg, self.records(self.proposal(invalid)))
        with self.assertRaisesRegex(ValueError, 'No admitted'):
            probe.current_product(self.cfg, {})

    def test_same_product_ties_still_need_explicit_supersession(self):
        old, new = self.proposal(20), self.proposal(20)
        new['payload']['rationale'] = 'Superseding reviewed fixture.'
        new['payload']['supersedes'] = [probe.common.canonical_hash(old)]
        self.assertEqual(probe.current_product(self.cfg, self.records(old, new)), new)

    def journal_fixture(self):
        import copy
        product = dict(PRODUCT, revision='a' * 40)
        digest = probe.common.canonical_hash(product)
        cache = {PATH: HASH}
        handoff = {'reference': 'ghcr.io/closure-labs/xo-nixpkg-products@sha256:' + 'c' * 64,
                   'sha256': 'd' * 64, 'producer': dict(repository=self.cfg['repository'],
                   sourceRevision=product['revision'], revision='e' * 40, runId=20, runAttempt=1,
                   workflow='.github/workflows/qualification.yml')}
        def receipt(name, expected):
            return {'schema': 1, 'productHash': digest, 'destination': name, 'status': 'verified',
                    'expected': copy.deepcopy(expected), 'observed': copy.deepcopy(expected),
                    'verifiedAt': '2026-11-08T12:00:00Z', 'verifier': 'f' * 64}
        doc = {'schema': 2, 'productHash': digest,
               'receipts': {'cache': receipt('cache', cache), 'handoff': receipt('handoff', handoff)},
               'steps': [{'name': 'cache', 'state': 'complete',
                          'identity': {'products': product['products'], 'roots': {}}},
                         {'name': 'handoff', 'state': 'complete', 'identity': copy.deepcopy(handoff)}]}
        return product, doc

    def snapshot(self, product, doc, tree_mutation=None):
        import base64, hashlib
        raw = json.dumps(doc).encode()
        sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        branch = 'automation/publication-' + probe.common.canonical_hash(product)
        tree = {'truncated': False, 'tree': [dict(path='journal.json', mode='100644', type='blob',
                                                sha=sha, size=len(raw))]}
        if tree_mutation:
            tree_mutation(tree)
        def api(endpoint):
            if endpoint.endswith('/git/ref/heads/' + branch):
                return {'ref': 'refs/heads/' + branch, 'object': {'sha': 'b' * 40, 'type': 'commit'}}
            if endpoint.endswith('/git/trees/' + 'b' * 40):
                return tree
            self.assertTrue(endpoint.endswith('/git/blobs/' + sha))
            return dict(sha=sha, size=len(raw), encoding='base64', content=base64.b64encode(raw).decode())
        return probe.publication_snapshot(self.cfg, product, api)

    def test_exact_completed_receipts_select_one_immutable_snapshot(self):
        product, doc = self.journal_fixture()
        endpoint, revision = self.snapshot(product, doc)
        self.assertTrue(endpoint.endswith(probe.common.canonical_hash(product)))
        self.assertEqual(revision, 'b' * 40)

    def test_missing_partial_stale_or_conflicting_receipts_block(self):
        import copy
        product, original = self.journal_fixture()
        mutations = [lambda d: d['receipts'].pop('cache'),
            lambda d: d['steps'].pop(),
            lambda d: d['steps'].append(copy.deepcopy(d['steps'][0])),
            lambda d: d['receipts']['cache']['observed'].update({PATH: 'wrong'}),
            lambda d: d.update(productHash='0' * 64),
            lambda d: d['steps'][0].update(identity={}),
            lambda d: d['receipts']['handoff']['expected']['producer'].update(sourceRevision='0' * 40)]
        for mutate in mutations:
            doc = copy.deepcopy(original)
            mutate(doc)
            with self.assertRaises(ValueError):
                self.snapshot(product, doc)
        with self.assertRaises(ValueError):
            probe.publication_snapshot(self.cfg, product, lambda endpoint: {})
        # Self-consistent receipts still cannot select another registry/source.
        for key, value in (('reference', 'ghcrXio/closure-labs/xo-nixpkg-products@sha256:' + 'c' * 64),
                           ('sourceRevision', '0' * 40)):
            doc = copy.deepcopy(original)
            for identity in (doc['receipts']['handoff']['expected'],
                             doc['receipts']['handoff']['observed'], doc['steps'][1]['identity']):
                if key == 'sourceRevision':
                    identity['producer'][key] = value
                else:
                    identity[key] = value
            with self.assertRaisesRegex(ValueError, 'handoff receipt'):
                self.snapshot(product, doc)
        for mutate in (lambda t: t.update(truncated=True),
                       lambda t: t['tree'][0].update(mode='120000'),
                       lambda t: t['tree'].append(dict(t['tree'][0]))):
            with self.assertRaises(ValueError):
                self.snapshot(product, original, mutate)

    def test_changed_main_or_journal_blocks_success(self):
        from unittest.mock import patch
        with patch.object(probe.common, 'main_revision', return_value='a' * 40):
            probe.unchanged(self.cfg, 'a' * 40, ('journal', 'b' * 40),
                            lambda _: {'object': {'sha': 'b' * 40}})
            with self.assertRaisesRegex(ValueError, 'publication changed'):
                probe.unchanged(self.cfg, 'a' * 40, ('journal', 'b' * 40),
                                lambda _: {'object': {'sha': 'c' * 40}})
            with self.assertRaisesRegex(ValueError, 'selection changed'):
                probe.unchanged(self.cfg, 'c' * 40, ('journal', 'b' * 40), lambda _: {})


if __name__ == '__main__':
    unittest.main()
