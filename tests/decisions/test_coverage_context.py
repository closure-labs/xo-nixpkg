"""Publication cannot reuse incomplete coverage or forget an empty policy review."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_core import CFG, ROOT, NAR, SHA, native, scan
import common
import reconciliation
import security_decisions


def context():
    return {'schema': 1, 'tcpPorts': [22, 443], 'udpPorts': [],
            'managementCIDRs': ['10.0.0.0/8'], 'ssh': {'PasswordAuthentication': False},
            'execution': {'xoUser': 'xo', 'User': 'xo', 'Group': 'xo'},
            'capabilities': [], 'ambientCapabilities': [],
            'helpers': {'enableNFS': False, 'enableCIFS': False, 'enableVHD': False, 'fileRestore': False},
            'sudo': [], 'mountsDir': '/run/xo'}


def empty_scan():
    value = scan()
    value['profiles']['maestro'].update(observations=[], securityContext=context())
    return value


def decision(value):
    return {'schema': 1, 'kind': 'security-findings', 'payload': {
        'disposition': 'accepted', 'profiles': {'maestro': []},
        'securityContexts': copy.deepcopy(common.security_contexts(value))}}


class CoverageContext(unittest.TestCase):
    def setUp(self):
        network = patch.object(common.authority, 'github_api', side_effect=AssertionError('unexpected network'))
        network.start()
        self.addCleanup(network.stop)

    def test_old_healthy_scan_cannot_satisfy_current_coverage(self):
        cfg = dict(CFG, requiredCoverage={'maestro': 'maestro-distribution-v2'})
        value = scan()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'scans.json'
            path.write_text(json.dumps(value))
            with patch.object(common, 'verify_producer', return_value=(SHA, '.github/workflows/ci.yml')), \
                    patch.object(common, 'attest'):
                with self.assertRaisesRegex(ValueError, 'required distribution coverage'):
                    common.scans(path, cfg)
                # Historical restoration authenticates original bytes without
                # upgrading the old report into publication-ready coverage.
                common.scans(path, cfg, allow_expired=True)
                with self.assertRaisesRegex(ValueError, 'required distribution coverage'):
                    common.scans(path, cfg)
                value['profiles']['maestro']['coverage'] = {
                    'contract': 'maestro-distribution-v2', 'manifest': {'roots': {'system': ROOT}}}
                path.write_text(json.dumps(value))
                common.scans(path, cfg)

    def test_coverage_marker_requires_scanned_manifest_roots(self):
        value = native()
        contract = 'maestro-distribution-v2'
        for manifest in [None, {}, {'roots': {}}, {'roots': {'boot': '/tmp/boot'}},
                         {'roots': {'boot': '/nix/store/' + 'c' * 32 + '-boot'}}]:
            with self.subTest(manifest=manifest):
                value['coverage'] = {'contract': contract, 'manifest': manifest}
                with self.assertRaisesRegex(ValueError, 'coverage roots'):
                    common.coverage_roots(value, contract)

    def test_complete_scan_cannot_retain_partial_distribution(self):
        cfg = dict(CFG, requiredCoverage={'maestro': 'maestro-distribution-v2'})
        value = scan()
        boot = '/nix/store/' + 'c' * 32 + '-boot'
        value['profiles']['maestro']['subjects'].append({'storePath': boot, 'narHash': NAR})
        value['profiles']['maestro']['coverage'] = {
            'contract': 'maestro-distribution-v2', 'manifest': {'roots': {'system': ROOT, 'boot': boot}}}
        product = {'schema': 1, 'repository': CFG['repository'], 'revision': SHA,
                   'products': {'maestro': {'storePath': ROOT, 'narHash': NAR}}, 'assets': {}}
        with tempfile.TemporaryDirectory() as directory, patch.object(common, 'attest_product'):
            path = Path(directory) / 'product.json'
            path.write_text(json.dumps(product))
            with self.assertRaisesRegex(ValueError, 'absent from retained product'):
                common.product(path, cfg, value)
            product['roots'] = {'boot': {'profile': 'maestro', 'storePath': boot, 'narHash': NAR}}
            path.write_text(json.dumps(product))
            common.product(path, cfg, value)

    def test_invalid_coverage_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            for coverage in [[], {'other': 'valid'}, {'maestro': ''}, {'maestro': True}]:
                with self.subTest(coverage=coverage):
                    path.write_text(json.dumps(dict(CFG, requiredCoverage=coverage)))
                    with self.assertRaisesRegex(ValueError, 'coverage policy'):
                        common.config(path)

    def test_empty_findings_still_bind_reviewed_policy(self):
        value = empty_scan()
        accepted = decision(value)
        with patch.object(common, 'active_security', return_value=('a' * 64, accepted)):
            self.assertEqual(common.admission(CFG, value, {})['status'], 'covered')
            expanded = copy.deepcopy(value)
            expanded['profiles']['maestro']['securityContext']['tcpPorts'].append(8443)
            with self.assertRaisesRegex(ValueError, 'policy changes require a human'):
                common.admission(CFG, expanded, {})

    def test_legacy_empty_baseline_cannot_invent_context_review(self):
        value = empty_scan()
        accepted = decision(value)
        del accepted['payload']['securityContexts']
        with patch.object(common, 'active_security', return_value=('a' * 64, accepted)):
            with self.assertRaisesRegex(ValueError, 'policy changes require a human'):
                common.admission(CFG, value, {})

    def test_known_context_cannot_disappear(self):
        value = empty_scan()
        accepted = decision(value)
        del value['profiles']['maestro']['securityContext']
        with patch.object(common, 'active_security', return_value=('a' * 64, accepted)):
            with self.assertRaisesRegex(ValueError, 'security context disappeared'):
                common.admission(CFG, value, {})

    def test_narrowed_context_reuses_empty_acceptance(self):
        value = empty_scan()
        accepted = decision(value)
        value['profiles']['maestro']['securityContext']['tcpPorts'] = [443]
        with patch.object(common, 'active_security', return_value=('a' * 64, accepted)):
            self.assertEqual(common.admission(CFG, value, {})['status'], 'covered')

    def test_legacy_nonempty_findings_preserve_original_context(self):
        current = native()
        current['securityContext'] = context()
        payload = {'profiles': {'maestro': security_decisions.normalize_findings(current, 'maestro')}}
        self.assertEqual(common.accepted_contexts(payload), {'maestro': context()})

    def test_context_cannot_move_between_profiles(self):
        with self.assertRaisesRegex(ValueError, 'profile security contexts'):
            common.accepted_contexts({'profiles': {'maestro': []}, 'securityContexts': {'other': context()}})

    def test_packet_rejects_policy_not_present_in_signed_scan(self):
        value = empty_scan()
        proposal = decision(value)
        producer = dict(value['producer'], repository=CFG['repository'], revision=SHA, sourceRevision=SHA)
        proposal['payload']['packet'] = {'reference': 'unused', 'sha256': 'a' * 64, 'producer': producer}
        proposal['payload']['supersedes'] = []
        proposal['payload']['securityContexts']['maestro']['tcpPorts'].append(8443)
        with patch.object(reconciliation.packets, 'fetch', return_value={'producer': producer}), \
                patch.object(reconciliation, 'scans', return_value=value):
            with self.assertRaisesRegex(ValueError, 'policy differs from authenticated'):
                reconciliation.validate_proposal_packet(proposal, CFG)

    def test_reconcile_proposes_policy_change_even_without_findings(self):
        value = empty_scan()
        previous = decision(value)
        value['profiles']['maestro']['securityContext']['tcpPorts'].append(8443)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'scans.json'
            path.write_text(json.dumps(value))
            with patch.object(reconciliation, 'ledger', return_value=(SHA, {})), \
                    patch.object(reconciliation, 'active_security', return_value=('a' * 64, previous)), \
                    patch.object(reconciliation, 'scans', return_value=value), \
                    patch.object(reconciliation.packets, 'push', return_value={'reference': 'unused'}), \
                    patch.object(reconciliation, 'validate_proposal_packet'), \
                    patch.object(reconciliation, 'propose', side_effect=lambda cfg, proposal: proposal):
                result = reconciliation.reconcile(CFG, path, None, 'security-findings', root, 'Review changed exposure')
        self.assertEqual(result['kind'], 'security-findings')
        self.assertEqual(result['payload']['profiles'], {'maestro': []})
        self.assertEqual(result['payload']['securityContexts'], common.security_contexts(value))


if __name__ == '__main__':
    unittest.main()
