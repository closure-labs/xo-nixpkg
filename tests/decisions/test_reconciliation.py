"""Historical evidence remains reviewable; only active leaves need live authority."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci/decisions'))
import common
import reconciliation
import decision_authority as authority
from test_core import CFG, Core, scan
from test_authority import GitHub, verify


def release(product, supersedes=None, rationale='First approval'):
    return {'schema': 1, 'kind': 'release-product', 'payload': {
        'product': product, 'disposition': 'accepted', 'rationale': rationale,
        'supersedes': supersedes or [],
        'packet': {'reference': common.packets.REGISTRY + '@sha256:' + 'a' * 64,
                   'sha256': 'b' * 64, 'producer': {}}}}


class QueueSecurityGraph(unittest.TestCase):
    def validate(self, proposals, *, mutate=None):
        documents, entries = {}, {}
        for index, proposal in enumerate(proposals, 1):
            sha = f'{index:040x}'
            documents[sha] = proposal
            entries[authority.proposal_path(proposal)] = ('blob', '100644', sha, len(json.dumps(proposal)))
        # Unrelated tree entries must not be interpreted as decisions.
        entries['ci/check.py'] = ('blob', '100644', 'f' * 40, 10)
        if mutate:
            mutate(entries)
        api = lambda endpoint: self.fail('Unexpected network request: ' + endpoint)
        with patch.object(authority, 'document_blob', side_effect=lambda api, repo, sha, size: documents[sha]), \
                patch.object(common, 'historical_provenance') as historical, \
                patch.object(common, 'authorize') as authorize, \
                patch.object(common, 'persisted_risk') as persisted:
            reconciliation.validate_queue_security_graph(entries, CFG['repository'], api, CFG)
            authorize.assert_not_called()
            persisted.assert_not_called()
            return historical

    def test_single_leaf_and_linear_history_grant_no_authority(self):
        parent = Core().proposal()
        self.validate([parent]).assert_not_called()
        child = Core().proposal(supersedes=[common.canonical_hash(parent)])
        self.validate([parent, child]).assert_called_once_with(CFG, parent, unittest.mock.ANY)

    def test_queued_sibling_is_rejected_even_when_each_proposal_has_valid_main_parent(self):
        parent = Core().proposal()
        first = Core().proposal(supersedes=[common.canonical_hash(parent)])
        second = deepcopy(first)
        second['payload']['rationale'] = 'A separately approved scan of the same scope.'
        with self.assertRaisesRegex(ValueError, 'concurrent decisions'):
            self.validate([parent, first, second])

    def test_complete_ledger_is_required(self):
        child = Core().proposal(supersedes=['a' * 64])
        with self.assertRaisesRegex(ValueError, 'supersession parents'):
            self.validate([child])
        with self.assertRaisesRegex(ValueError, 'complete Git tree'):
            self.validate([])

    def test_git_blob_identity_and_canonical_path_are_required(self):
        proposal = Core().proposal()
        def symlink(entries):
            path = authority.proposal_path(proposal)
            kind, _, sha, size = entries[path]
            entries[path] = (kind, '120000', sha, size)
        with self.assertRaisesRegex(ValueError, 'regular Git blobs'):
            self.validate([proposal], mutate=symlink)
        def rename(entries):
            entries['automation/decisions/security/' + 'f' * 64 + '.json'] = entries.pop(authority.proposal_path(proposal))
        with self.assertRaisesRegex(ValueError, 'canonical Git tree path'):
            self.validate([proposal], mutate=rename)


class Reconciliation(unittest.TestCase):
    def test_historical_bot_merge_provenance_does_not_depend_on_departed_reviewer(self):
        api = GitHub()
        api.members = []
        api.reviews = []
        result = verify(api, require_live_review=False)
        self.assertEqual(result['status'], 'historical-provenance')
        self.assertIsNone(result['reviewer'])
        self.assertFalse(any('/reviews?' in endpoint or '/teams/' in endpoint for endpoint in api.calls))
        with self.assertRaises(ValueError):
            verify(api)  # The same historical record grants no current authority.
        with self.assertRaisesRegex(ValueError, 'Historical provenance cannot authorize'):
            verify(api, require_merged=False, require_live_review=False)
        api.pr['merged'] = False
        with self.assertRaises(ValueError):
            verify(api, require_live_review=False)

    def test_release_reaffirmation_selects_one_live_leaf_and_authenticates_parent_history(self):
        product = {'schema': 1, 'assets': {'release.iso': 'a' * 64}}
        parent = release(product)
        parent_hash = common.canonical_hash(parent)
        child = release(product, [parent_hash], 'Reaffirmed by current maintainer')
        child_hash = common.canonical_hash(child)
        with patch.object(common, 'historical_provenance') as history, patch.object(common, 'authorize') as live:
            selected, proposal = common.active_release(CFG, {parent_hash: parent, child_hash: child}, product)
            self.assertEqual(selected, child_hash)
            self.assertEqual(proposal, child)
            history.assert_called_once_with(CFG, parent, None)
            live.assert_called_once_with(CFG, child, None)
        with patch.object(common, 'historical_provenance', side_effect=ValueError('forged parent')):
            with self.assertRaisesRegex(ValueError, 'forged parent'):
                common.active_release(CFG, {parent_hash: parent, child_hash: child}, product)
        unrelated = release(product, rationale='Parallel unsuperseded decision')
        with self.assertRaisesRegex(ValueError, 'Ambiguous release'):
            common.active_release(CFG, {parent_hash: parent, common.canonical_hash(unrelated): unrelated}, product, authenticate=False)
        different = release({'assets': {'other': 'c' * 64}}, [parent_hash])
        with self.assertRaisesRegex(ValueError, 'preserve exact product'):
            common.active_release(CFG, {parent_hash: parent, common.canonical_hash(different): different}, different['payload']['product'], authenticate=False)

    def test_packet_uses_authenticated_historical_health_without_granting_fresh_admission(self):
        native_scan = scan()
        producer = dict(native_scan['producer'], repository=CFG['repository'], revision=native_scan['revision'], sourceRevision=native_scan['revision'])
        findings = {profile: common.evaluate(value, profile)['findings'] for profile, value in native_scan['profiles'].items()}
        proposal = {'schema': 1, 'kind': 'security-findings', 'payload': {
            'disposition': 'accepted', 'rationale': 'Historical evidence is reviewable', 'profiles': findings, 'supersedes': [],
            'packet': {'reference': common.packets.REGISTRY + '@sha256:' + 'a' * 64, 'sha256': 'b' * 64, 'producer': producer}}}
        with patch.object(reconciliation.packets, 'fetch', return_value={'producer': producer}), \
                patch.object(reconciliation, 'scans', return_value=native_scan) as verify_scan, \
                patch.object(reconciliation, 'ledger', return_value=('a' * 40, {})), \
                patch.object(reconciliation, 'active_security', return_value=(None, None)), \
                patch.object(reconciliation, 'main_revision', return_value='a' * 40):
            reconciliation.validate_proposal_packet(proposal, CFG)
            self.assertEqual(verify_scan.call_args.kwargs, {'allow_expired': True})
            forged = deepcopy(proposal)
            forged['payload']['profiles']['maestro'] = []
            with self.assertRaisesRegex(ValueError, 'differ from complete'):
                reconciliation.validate_proposal_packet(forged, CFG)

    def test_reconcile_reaffirms_product_after_current_reviewer_departure(self):
        native_scan = scan()
        product = {'schema': 1, 'repository': CFG['repository'], 'revision': native_scan['revision'],
                   'products': {}, 'assets': {}}
        parent = release(product)
        digest = common.canonical_hash(parent)
        producer = dict(native_scan['producer'], repository=CFG['repository'], revision=native_scan['revision'], sourceRevision=native_scan['revision'])
        packet = {'reference': common.packets.REGISTRY + '@sha256:' + 'a' * 64, 'sha256': 'b' * 64, 'producer': producer}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scan_path, product_path = root / 'scans.json', root / 'product.json'
            scan_path.write_text(json.dumps(native_scan))
            product_path.write_text(json.dumps(product))
            with patch.object(reconciliation, 'ledger', return_value=('a' * 40, {digest: parent})), \
                    patch.object(reconciliation, 'active_security', return_value=(None, None)), \
                    patch.object(reconciliation, 'scans', return_value=native_scan), \
                    patch.object(reconciliation, 'product', return_value=product), \
                    patch.object(reconciliation, 'authorize', side_effect=authority.HumanDecisionRequired('departed')), \
                    patch.object(reconciliation, 'historical_provenance') as historical, \
                    patch.object(reconciliation.packets, 'push', return_value=packet), \
                    patch.object(reconciliation, 'validate_proposal_packet'), \
                    patch.object(reconciliation, 'propose', side_effect=lambda cfg, proposal: proposal):
                result = reconciliation.reconcile(CFG, scan_path, product_path, 'release-product', root, 'New maintainer reaffirmation')
                self.assertEqual(result['payload']['supersedes'], [digest])
                self.assertEqual(result['payload']['product'], product)
                historical.assert_called_once_with(CFG, parent)


class MetadataFirstProposals(unittest.TestCase):
    def setUp(self):
        self.native = scan()
        self.producer = dict(self.native['producer'], repository=CFG['repository'],
                             revision=self.native['revision'], sourceRevision=self.native['revision'])
        self.identity = {'schema': 1, 'assets': {}}

    def proposal(self, kind):
        value = release(self.identity)
        value['kind'] = kind
        value['payload']['packet']['producer'] = self.producer
        if kind == 'security-findings':
            del value['payload']['product']
            value['payload']['profiles'] = {
                p: common.evaluate(s, p)['findings'] for p, s in self.native['profiles'].items()}
        return value

    def test_stale_security_and_product_parents_fetch_no_packet(self):
        for kind, selector in [('security-findings', 'active_security'), ('release-product', 'active_release')]:
            with self.subTest(kind=kind), \
                    patch.object(reconciliation, 'ledger', return_value=('a' * 40, {})), \
                    patch.object(reconciliation, selector, return_value=('b' * 64, None)), \
                    patch.object(reconciliation.packets, 'fetch') as fetch:
                with self.assertRaisesRegex(ValueError, 'stale supersession parent'):
                    reconciliation.validate_proposal_packet(self.proposal(kind), CFG)
                fetch.assert_not_called()

    def test_unavailable_parent_metadata_is_not_an_empty_ledger(self):
        with patch.object(reconciliation, 'ledger', side_effect=ValueError('metadata unavailable')), \
                patch.object(reconciliation.packets, 'fetch') as fetch:
            with self.assertRaisesRegex(ValueError, 'metadata unavailable'):
                reconciliation.validate_proposal_packet(self.proposal('security-findings'), CFG)
            fetch.assert_not_called()

    def test_matching_revision_loads_immutable_parents_once_and_still_verifies_packet(self):
        for kind, selector in [('security-findings', 'active_security'), ('release-product', 'active_release')]:
            with self.subTest(kind=kind), \
                    patch.object(reconciliation, 'ledger', return_value=('a' * 40, {})) as ledger, \
                    patch.object(reconciliation, selector, return_value=(None, None)), \
                    patch.object(reconciliation, 'main_revision', return_value='a' * 40) as current, \
                    patch.object(reconciliation.packets, 'fetch', return_value={'producer': self.producer}) as fetch, \
                    patch.object(reconciliation, 'scans', return_value=self.native) as scans, \
                    patch.object(reconciliation, 'product', return_value=self.identity), \
                    patch.object(reconciliation, 'authorize') as authorize:
                reconciliation.validate_proposal_packet(self.proposal(kind), CFG)
                ledger.assert_called_once_with(CFG)
                current.assert_called_once_with(CFG)
                fetch.assert_called_once()
                scans.assert_called_once()
                authorize.assert_not_called()  # Parent observations grant no human authority.

    def test_parent_advance_during_packet_verification_blocks_both_kinds(self):
        for kind, selector in [('security-findings', 'active_security'), ('release-product', 'active_release')]:
            with self.subTest(kind=kind), \
                    patch.object(reconciliation, 'ledger', side_effect=[('a' * 40, {}), ('b' * 40, {})]) as ledger, \
                    patch.object(reconciliation, selector, side_effect=[(None, None), ('c' * 64, None)]), \
                    patch.object(reconciliation, 'main_revision', return_value='b' * 40), \
                    patch.object(reconciliation.packets, 'fetch', return_value={'producer': self.producer}) as fetch, \
                    patch.object(reconciliation, 'scans', return_value=self.native), \
                    patch.object(reconciliation, 'product', return_value=self.identity):
                with self.assertRaisesRegex(ValueError, 'stale supersession parent'):
                    reconciliation.validate_proposal_packet(self.proposal(kind), CFG)
                self.assertEqual(ledger.call_count, 2)
                fetch.assert_called_once()

    def test_unrelated_main_advance_reloads_and_accepts_unchanged_parents(self):
        with patch.object(reconciliation, 'ledger', side_effect=[('a' * 40, {}), ('b' * 40, {})]) as ledger, \
                patch.object(reconciliation, 'active_security', return_value=(None, None)), \
                patch.object(reconciliation, 'main_revision', return_value='b' * 40), \
                patch.object(reconciliation.packets, 'fetch', return_value={'producer': self.producer}), \
                patch.object(reconciliation, 'scans', return_value=self.native):
            reconciliation.validate_proposal_packet(self.proposal('security-findings'), CFG)
            self.assertEqual(ledger.call_count, 2)

    def test_failed_final_revision_read_blocks_after_packet_verification(self):
        with patch.object(reconciliation, 'ledger', return_value=('a' * 40, {})), \
                patch.object(reconciliation, 'active_security', return_value=(None, None)), \
                patch.object(reconciliation, 'main_revision', side_effect=ValueError('revision unavailable')), \
                patch.object(reconciliation.packets, 'fetch', return_value={'producer': self.producer}) as fetch, \
                patch.object(reconciliation, 'scans', return_value=self.native):
            with self.assertRaisesRegex(ValueError, 'revision unavailable'):
                reconciliation.validate_proposal_packet(self.proposal('security-findings'), CFG)
            fetch.assert_called_once()

    def test_parent_match_never_bypasses_invalid_packet_producer(self):
        with patch.object(reconciliation, 'ledger', return_value=('a' * 40, {})), \
                patch.object(reconciliation, 'active_security', return_value=(None, None)), \
                patch.object(reconciliation.packets, 'fetch', return_value={'producer': {}}):
            with self.assertRaisesRegex(ValueError, 'Packet producer differs'):
                reconciliation.validate_proposal_packet(self.proposal('security-findings'), CFG)

    def test_forged_release_parent_history_blocks_before_payload(self):
        proposal = self.proposal('release-product')
        proposal['payload']['supersedes'] = ['c' * 64]
        with patch.object(reconciliation, 'ledger', return_value=('a' * 40, {})), \
                patch.object(reconciliation, 'active_release', return_value=('c' * 64, {})), \
                patch.object(reconciliation, 'historical_provenance', side_effect=ValueError('forged parent')), \
                patch.object(reconciliation.packets, 'fetch') as fetch:
            with self.assertRaisesRegex(ValueError, 'forged parent'):
                reconciliation.validate_proposal_packet(proposal, CFG)
            fetch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
