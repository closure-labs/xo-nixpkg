"""Exercise the adapted trust boundaries without GitHub or registry credentials."""
import copy
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci/decisions'))
import common
import decision_authority as authority
import security_decisions as findings
import check as decision_check
from recovery import validate_journal


CFG = {'schema': 1, 'repository': 'closure-labs/maestro', 'enabled': False,
       'botLogin': 'review[bot]', 'appId': 123, 'profiles': ['maestro'],
       'policyPath': 'nix/automation/decision-policy.json',
       'producerWorkflows': ['.github/workflows/ci.yml']}
ROOT = '/nix/store/' + 'a' * 32 + '-runtime'
NAR = 'sha256-' + 'A' * 43 + '='
SHA = 'b' * 40


def native():
    now = dt.datetime.now(dt.timezone.utc)
    return {'status': 'complete', 'scannerHealth': 'healthy', 'scannedAt': (now - dt.timedelta(minutes=5)).isoformat(),
            'database': {'valid': True, 'built': (now - dt.timedelta(hours=1)).isoformat()},
            'subjects': [{'storePath': ROOT, 'narHash': NAR}],
            'observations': [{'component': 'pkg:npm/lodash@4.17.15', 'advisory': 'CVE-2020-8203',
                              'aliases': [], 'severity': 'High', 'knownExploited': False, 'cvss': 7.4,
                              'locations': [ROOT + '/lib/module.js'], 'locationCoverage': 'complete',
                              'fixVersions': ['4.17.21'], 'exposureBindings': [
                                  {'location': ROOT + '/lib/module.js', 'outputName': 'out',
                                   'relativePath': 'lib/module.js'}]}]}


def scan():
    now = dt.datetime.now(dt.timezone.utc)
    return {'schema': 1, 'repository': CFG['repository'], 'revision': SHA,
            'producer': {'workflow': '.github/workflows/ci.yml', 'runId': 5, 'runAttempt': 2},
            'scannedAt': (now - dt.timedelta(minutes=10)).isoformat(),
            'expiresAt': (now + dt.timedelta(hours=1)).isoformat(), 'profiles': {'maestro': native()}}


class Core(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value))
        return path

    def test_runtime_packaging_and_npins_source_changes_require_governed_review(self):
        for path in ['default.nix', 'pkgs/maestro-menu/src/main.rs', 'pkgs/xen-orchestra/default.nix',
                     'npins/sources.json', 'scripts/update.sh']:
            with self.subTest(path=path):
                self.assertTrue(decision_check.governed(path))

    def proposal(self, disposition='accepted', supersedes=None):
        return {'schema': 1, 'kind': 'security-findings', 'payload': {
            'disposition': disposition, 'rationale': 'Reviewed native evidence.',
            'profiles': {'maestro': findings.normalize_findings(native(), 'maestro')},
            'packet': {'reference': common.packets.REGISTRY + '@sha256:' + 'a' * 64,
                       'sha256': 'b' * 64}, 'supersedes': supersedes or []}}

    def test_disabled_publication_never_reaches_network(self):
        with patch.object(authority, 'github_api', side_effect=AssertionError('network')):
            with self.assertRaisesRegex(ValueError, 'disabled'):
                common.gate(CFG, self.root / 'scan')

    def test_live_policy_cannot_be_enabled_by_local_file(self):
        local = dict(CFG, enabled=True)
        path = self.write('policy.json', local)
        with patch.object(common.authority, 'document_at', return_value=CFG):
            with self.assertRaisesRegex(ValueError, 'differs from current main'):
                common.config(path, live=True, api=lambda _: {'object': {'sha': SHA}})

    def test_wrong_named_check_app_does_not_satisfy_readiness(self):
        rules = [{'type': 'required_status_checks', 'parameters': {'required_status_checks': [
            {'context': 'Maintainer decision authority', 'integration_id': 999}]}}]
        with self.assertRaisesRegex(ValueError, 'App-bound'):
            common.required_check(CFG, lambda _: rules)
        rules[0]['parameters']['required_status_checks'][0]['integration_id'] = 123
        common.required_check(CFG, lambda _: rules)

    def test_truncated_ledger_is_not_empty_baseline(self):
        def api(endpoint):
            return {'truncated': True, 'tree': []} if '/git/trees/' in endpoint else {'object': {'sha': SHA}}
        with self.assertRaisesRegex(ValueError, 'Complete'):
            common.ledger(CFG, api)

    def test_symlink_and_noncanonical_ledger_files_rejected(self):
        for mode, path in [('120000', 'automation/decisions/security/' + 'a' * 64 + '.json'),
                           ('100644', 'automation/decisions/security/readme.json')]:
            def api(endpoint):
                return {'truncated': False, 'tree': [{'path': path, 'type': 'blob', 'mode': mode}]} if '/git/trees/' in endpoint else {'object': {'sha': SHA}}
            with self.assertRaises(ValueError):
                common.ledger(CFG, api)

    def test_initial_empty_scan_still_requires_human(self):
        with self.assertRaisesRegex(ValueError, 'human risk acceptance'):
            common.admission(CFG, scan(), {})

    def test_rejected_decision_is_authentic_but_cannot_publish(self):
        proposal = self.proposal('rejected')
        with patch.object(common, 'authorize', return_value={}):
            with self.assertRaisesRegex(ValueError, 'human risk acceptance'):
                common.admission(CFG, scan(), {findings.canonical_hash(proposal): proposal})

    def test_concurrent_decision_leaves_fail_closed(self):
        one, two = self.proposal(), self.proposal('rejected')
        with self.assertRaisesRegex(ValueError, 'Ambiguous concurrent'):
            common.active_security(CFG, {findings.canonical_hash(p): p for p in [one, two]})

    def test_revocation_preserves_exact_parent_scope(self):
        parent = self.proposal()
        digest = findings.canonical_hash(parent)
        revoke = {'schema': 1, 'kind': 'security-revocation',
                  'payload': dict(parent['payload'], disposition='revoked', supersedes=[digest])}
        revoke['payload']['profiles'] = {'maestro': []}
        with self.assertRaisesRegex(ValueError, 'exact accepted scope'):
            common.active_security(CFG, {digest: parent, findings.canonical_hash(revoke): revoke})

    def test_stable_exposure_carries_version_and_store_hash_changes(self):
        old = findings.normalize_findings(native(), 'maestro')
        current = native()
        current['observations'][0]['component'] = 'pkg:npm/lodash@4.17.16'
        location = '/nix/store/' + 'z' * 32 + '-rebuilt/lib/module.js'
        current['observations'][0]['locations'] = [location]
        current['observations'][0]['exposureBindings'][0]['location'] = location
        self.assertEqual(findings.evaluate(current, 'maestro', old)['status'], 'covered')

    def test_exposure_mapping_cannot_hide_added_file(self):
        value = native()
        value['observations'][0]['locations'].append(ROOT + '/bin/new-file')
        with self.assertRaisesRegex(ValueError, 'Incomplete stable exposure'):
            findings.normalize_findings(value, 'maestro')

    def test_exposure_mapping_cannot_claim_different_relative_file(self):
        value = native()
        value['observations'][0]['exposureBindings'][0]['relativePath'] = 'bin/other'
        with self.assertRaisesRegex(ValueError, 'Unbound stable exposure'):
            findings.normalize_findings(value, 'maestro')

    def test_complete_producer_must_be_same_repo_revision_attempt_and_workflow(self):
        path = self.write('scans.json', scan())
        producer = {'id': 5, 'run_attempt': 2, 'head_sha': SHA, 'head_branch': 'main', 'event': 'push',
                    'path': '.github/workflows/ci.yml', 'status': 'completed', 'conclusion': 'success',
                    'repository': {'full_name': CFG['repository']}}
        with patch.object(common, 'attest', return_value=[]):
            common.scans(path, CFG, lambda _: producer)
            for key, value in [('head_sha', 'c' * 40), ('head_branch', 'feature'), ('event', 'pull_request'),
                               ('path', '.github/workflows/other.yml'), ('conclusion', 'failure'), ('status', 'in_progress')]:
                changed = dict(producer, **{key: value})
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'Untrusted'):
                    common.scans(path, CFG, lambda _: changed)

    def test_stale_native_health_cannot_be_accepted(self):
        value = scan()
        value['expiresAt'] = value['scannedAt']
        with self.assertRaisesRegex(ValueError, 'Expired'):
            common.scans(self.write('scans.json', value), CFG, lambda _: {})

    def test_envelope_cannot_refresh_old_observation_or_stale_database(self):
        producer = {'id': 5, 'run_attempt': 2, 'head_sha': SHA, 'head_branch': 'main', 'event': 'push',
                    'path': '.github/workflows/ci.yml', 'status': 'completed', 'conclusion': 'success',
                    'repository': {'full_name': CFG['repository']}}
        value = scan()
        now = dt.datetime.now(dt.timezone.utc)
        with patch.object(common, 'attest', return_value=[]):
            old_native = copy.deepcopy(value)
            old_native['profiles']['maestro']['scannedAt'] = (now - dt.timedelta(days=2)).isoformat()
            with self.assertRaisesRegex(ValueError, 'predates envelope'):
                common.scans(self.write('scans.json', old_native), CFG, lambda _: producer)
            old_database = copy.deepcopy(value)
            old_database['profiles']['maestro']['database']['built'] = (now - dt.timedelta(hours=49)).isoformat()
            with self.assertRaisesRegex(ValueError, 'database is stale'):
                common.scans(self.write('scans.json', old_database), CFG, lambda _: producer)
            invalid = copy.deepcopy(value)
            invalid['profiles']['maestro']['database']['valid'] = False
            with self.assertRaisesRegex(ValueError, 'database is invalid'):
                common.scans(self.write('scans.json', invalid), CFG, lambda _: producer)
            extended = copy.deepcopy(value)
            extended['expiresAt'] = (common.timestamp(extended['scannedAt']) + dt.timedelta(hours=25)).isoformat()
            with self.assertRaisesRegex(ValueError, 'Expired or future'):
                common.scans(self.write('scans.json', extended), CFG, lambda _: producer)
            historical = copy.deepcopy(value)
            for field in ('scannedAt', 'expiresAt'):
                historical[field] = (common.timestamp(historical[field]) - dt.timedelta(days=5)).isoformat()
            historical['profiles']['maestro']['scannedAt'] = (common.timestamp(value['profiles']['maestro']['scannedAt']) - dt.timedelta(days=5)).isoformat()
            historical['profiles']['maestro']['database']['built'] = (common.timestamp(value['profiles']['maestro']['database']['built']) - dt.timedelta(days=5)).isoformat()
            common.scans(self.write('scans.json', historical), CFG, lambda _: producer, allow_expired=True)

    def test_current_trusted_producer_can_rescan_unchanged_historical_product(self):
        value = scan()
        new_revision = 'c' * 40
        value['producer']['revision'] = new_revision
        producer = {'id': 5, 'run_attempt': 2, 'head_sha': new_revision, 'head_branch': 'main', 'event': 'workflow_dispatch',
                    'path': '.github/workflows/ci.yml', 'status': 'completed', 'conclusion': 'success',
                    'repository': {'full_name': CFG['repository']}}
        def api(endpoint):
            return {'status': 'ahead'} if '/compare/' in endpoint else producer
        with patch.object(common, 'attest', return_value=[]) as verify:
            common.scans(self.write('scans.json', value), CFG, api)
            self.assertEqual(verify.call_args.args[2], new_revision)
        with patch.object(common, 'attest', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'ancestor of trusted producer'):
                common.scans(self.write('scans.json', value), CFG,
                             lambda endpoint: {'status': 'diverged'} if '/compare/' in endpoint else producer)

    def test_product_uses_original_revision_even_after_later_scan(self):
        value = {'schema': 1, 'repository': CFG['repository'], 'revision': SHA,
                 'products': {'maestro': {'storePath': ROOT, 'narHash': NAR}}, 'assets': {}}
        refreshed = scan()
        refreshed['producer']['revision'] = 'c' * 40
        with patch.object(common, 'attest', return_value=[]) as verify:
            common.product(self.write('product.json', value), CFG, refreshed)
            self.assertEqual(verify.call_args.args[2], SHA)

    def test_reusable_release_caller_and_signer_are_distinct_allowlisted_identities(self):
        cfg = dict(CFG, producerWorkflows=['.github/workflows/release-continuation.yml', '.github/workflows/release.yml'])
        value = scan()
        value['producer'].update(workflow='.github/workflows/release-continuation.yml',
                                 signerWorkflow='.github/workflows/release.yml', revision='c' * 40)
        caller = {'id': 5, 'run_attempt': 2, 'head_sha': 'c' * 40, 'head_branch': 'main',
                  'event': 'workflow_run', 'path': '.github/workflows/release-continuation.yml',
                  'status': 'completed', 'conclusion': 'success', 'repository': {'full_name': CFG['repository']}}
        def api(endpoint):
            return {'status': 'ahead'} if '/compare/' in endpoint else caller
        with patch.object(common, 'attest', return_value=[]) as verify:
            common.scans(self.write('scans.json', value), cfg, api)
        self.assertEqual(verify.call_args.args[2:], ('c' * 40, '.github/workflows/release.yml'))
        with patch.object(common, 'attest', side_effect=AssertionError('No signature check for invalid caller')):
            with self.assertRaisesRegex(ValueError, 'Untrusted'):
                common.scans(self.write('scans.json', value), cfg,
                             lambda endpoint: {'status': 'ahead'} if '/compare/' in endpoint
                             else dict(caller, path='.github/workflows/release.yml'))

    def test_reusable_signer_must_be_independently_allowlisted(self):
        value = scan()
        value['producer']['signerWorkflow'] = '.github/workflows/untrusted.yml'
        with self.assertRaisesRegex(ValueError, 'Invalid producer identity'):
            common.scans(self.write('scans.json', value), CFG, lambda _: {})

    def test_historical_product_keeps_original_reusable_builder_after_refresh(self):
        cfg = dict(CFG, producerWorkflows=['.github/workflows/release-continuation.yml',
                                          '.github/workflows/release.yml', '.github/workflows/security.yml'])
        identity = {'schema': 1, 'repository': CFG['repository'], 'revision': SHA,
                    'products': {'maestro': {'storePath': ROOT, 'narHash': NAR}}, 'assets': {}}
        refreshed = scan()
        refreshed['producer'] = {'workflow': '.github/workflows/security.yml', 'revision': 'e' * 40,
                                 'runId': 10, 'runAttempt': 1}
        original = {'workflow': '.github/workflows/release-continuation.yml', 'signerWorkflow': '.github/workflows/release.yml',
                    'revision': 'c' * 40, 'runId': 5, 'runAttempt': 2}
        refreshed['productProducer'] = original
        caller = {'id': 5, 'run_attempt': 2, 'head_sha': 'c' * 40, 'head_branch': 'main',
                  'event': 'workflow_run', 'path': original['workflow'], 'status': 'completed',
                  'conclusion': 'success', 'repository': {'full_name': CFG['repository']}}
        calls = []
        def api(endpoint):
            calls.append(endpoint)
            if '/compare/' in endpoint:
                return {'status': 'ahead'}
            if '/git/ref/' in endpoint:
                return {'object': {'sha': 'f' * 40}}
            return caller
        with patch.object(common, 'attest', return_value=[]) as verify:
            common.product(self.write('product.json', identity), cfg, refreshed, api)
        self.assertEqual(verify.call_args.args[2:], ('c' * 40, '.github/workflows/release.yml'))
        self.assertTrue(any(SHA + '...' + 'c' * 40 in call for call in calls))
        self.assertTrue(any('c' * 40 + '...' + 'f' * 40 in call for call in calls))
        with patch.object(common, 'attest', side_effect=AssertionError('No signature for divergent source')):
            with self.assertRaisesRegex(ValueError, 'ancestor of trusted producer'):
                common.product(self.write('product.json', identity), cfg, refreshed,
                               lambda endpoint: {'status': 'diverged'} if '/compare/' in endpoint else caller)

    def test_original_product_producer_must_still_be_on_protected_main_history(self):
        metadata = {'workflow': '.github/workflows/ci.yml', 'revision': SHA, 'runId': 5, 'runAttempt': 2}
        caller = {'id': 5, 'run_attempt': 2, 'head_sha': SHA, 'head_branch': 'main', 'event': 'push',
                  'path': '.github/workflows/ci.yml', 'status': 'completed', 'conclusion': 'success',
                  'repository': {'full_name': CFG['repository']}}
        def api(endpoint):
            if '/compare/' in endpoint:
                return {'status': 'diverged'}
            if '/git/ref/' in endpoint:
                return {'object': {'sha': 'f' * 40}}
            return caller
        with self.assertRaisesRegex(ValueError, 'current protected main ancestry'):
            common.verify_producer(CFG, metadata, SHA, api, require_main=True)

    def test_product_cannot_add_unscanned_distribution_root(self):
        value = {'schema': 1, 'repository': CFG['repository'], 'revision': SHA,
                 'products': {'maestro': {'storePath': ROOT, 'narHash': NAR}}, 'assets': {}}
        with patch.object(common, 'attest', return_value=[]):
            common.product(self.write('product.json', value), CFG, scan())
            value['roots'] = {'tools': {'storePath': ROOT + '-tools', 'narHash': NAR, 'profile': 'maestro'}}
            with self.assertRaisesRegex(ValueError, 'absent from authenticated'):
                common.product(self.write('product.json', value), CFG, scan())

    def test_recovery_cannot_change_approved_product_or_accept_invalid_steps(self):
        product = {'assets': {'release.iso': 'a' * 64}}
        journal = {'schema': 1, 'productHash': findings.canonical_hash(product),
                   'steps': {'release': 'pending'}}
        validate_journal(journal, product)
        with self.assertRaisesRegex(ValueError, 'differs from exact'):
            validate_journal(journal, {'assets': {'release.iso': 'b' * 64}})
        journal['steps']['invalid/step'] = 'pending'
        with self.assertRaisesRegex(ValueError, 'Invalid recovery'):
            validate_journal(journal, product)


if __name__ == '__main__':
    unittest.main()
