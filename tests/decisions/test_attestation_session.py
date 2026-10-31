"""Mock transport only: hosted gh remains the cryptographic verifier."""
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci/decisions'))
import attestation_session as m
import common
import decision_authority as authority

REPO = 'closure-labs/xo-nixpkg'
REV = 'b' * 40
WORKFLOW = '.github/workflows/qualification.yml'


class Session(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.session = self.root / 'session'
        self.session.mkdir(mode=0o700)
        self.subject = self.root / 'product.json'
        self.subject.write_bytes(b'public fixture')
        self.verifier = self.root / 'gh'
        self.verifier.write_bytes(b'pinned verifier fixture')
        self.cfg = {'repository': REPO, 'enabled': True, 'appId': 5384448,
                    'producerWorkflows': [WORKFLOW], 'profiles': ['xo-latest']}
        self.producer = {'runId': 7, 'runAttempt': 2, 'workflow': WORKFLOW, 'revision': REV}
        self.commands = []
        self.api_calls = []
        self.api_values = []
        self.failed = False
        self.mutate = False
        self.output = None
        self.environment = patch.dict(os.environ, {m.VARIABLE: str(self.session)})
        self.environment.start(); self.addCleanup(self.environment.stop)
        self.which = patch.object(m.shutil, 'which', return_value=str(self.verifier))
        self.which.start(); self.addCleanup(self.which.stop)

    def api(self, endpoint):
        self.api_calls.append(endpoint)
        return self.api_values.pop(0) if self.api_values else {
            'full_name': REPO, 'id': 17, 'owner': {'login': 'closure-labs', 'id': 19}}

    def command(self, arguments):
        self.commands.append(arguments)
        if self.failed:
            raise subprocess.CalledProcessError(1, 'sanitized-verification-failed')
        digest = hashlib.sha256(self.subject.read_bytes()).hexdigest()
        if '--bundle' in arguments:
            bundle = Path(arguments[arguments.index('--bundle') + 1])
            for line in bundle.read_bytes().splitlines():
                value = json.loads(line)
                if value.get('fixtureSignature') != 'valid' or value.get('fixtureSubject') != digest:
                    raise subprocess.CalledProcessError(1, 'sanitized-signature-or-subject-failure')
        if self.mutate:
            self.subject.write_bytes(b'swapped during verification')
        if self.output is not None:
            return self.output
        return [{'attestation': {'bundle': {'mediaType': 'application/vnd.dev.sigstore.bundle.v0.3+json',
                                            'fixtureSignature': 'valid', 'fixtureSubject': digest}},
                 'verificationResult': {'statement': {'subject': [{'name': self.subject.name,
                                                                  'digest': {'sha256': digest}}],
                     'predicate': {'runDetails': {'metadata': {'invocationId':
                         f'https://github.com/{REPO}/actions/runs/7/attempts/2'}}}}}}]

    def verify(self, cfg=None, producer=None, revision=REV, workflow=WORKFLOW):
        args = ['gh', 'attestation', 'verify', str(self.subject), '--repo', REPO,
                '--source-digest', revision, '--signer-workflow', REPO + '/' + workflow,
                '--cert-oidc-issuer', m.ISSUER,
                '--predicate-type', m.PREDICATE, '--deny-self-hosted-runners']
        return m.verify(self.subject, cfg or self.cfg, revision, workflow,
                        producer or self.producer, args, self.command, self.api)

    def counts(self):
        return (sum('--bundle' not in a for a in self.commands),
                sum('--bundle' in a for a in self.commands))

    def test_eleven_checkpoints_fetch_once_but_verify_eleven_times(self):
        for _ in range(11):
            self.verify()
        self.assertEqual(self.counts(), (1, 10))
        self.assertEqual(len(self.api_calls), 22)  # live name/ID binding before and after every verification
        self.assertEqual(len(list(self.session.glob('*.json'))), 1)
        entry = json.loads(next(self.session.glob('*.json')).read_text())
        self.assertNotIn('verificationResult', entry)
        self.assertNotIn('authority', entry)

    def test_changed_subject_policy_issuer_workflow_attempt_and_verifier_miss(self):
        variants = [lambda: self.subject.write_bytes(b'other public bytes'),
                    lambda: self.cfg.update(enabled=False),
                    lambda: self.producer.update(runAttempt=3),
                    lambda: self.cfg.update(producerWorkflows=['.github/workflows/other.yml']),
                    lambda: self.verifier.write_bytes(b'changed verifier')]
        for mutate in variants:
            with self.subTest(mutate=mutate):
                for entry in self.session.glob('*.json'):
                    entry.unlink()
                self.cfg['enabled'] = True
                self.producer['runAttempt'] = 2
                self.commands.clear()
                self.verify()
                mutate()
                self.verify()
                self.assertEqual(self.counts()[0], 2)
        for entry in self.session.glob('*.json'):
            entry.unlink()
        self.producer['runAttempt'] = 2
        self.commands.clear(); self.verify()
        with patch.object(m, 'ISSUER', 'https://issuer.invalid'):
            self.verify()
        self.assertEqual(self.counts()[0], 2)

    def test_changed_source_workflow_and_run_do_not_reuse_material(self):
        self.verify()
        self.verify(revision='c' * 40)
        self.verify(workflow='.github/workflows/other.yml')
        self.verify(producer=dict(self.producer, runId=8))
        self.assertEqual(self.counts(), (4, 0))

    def test_failed_verification_never_populates_material(self):
        self.failed = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.verify()
        self.assertEqual(list(self.session.glob('*.json')), [])
        self.failed = False
        self.verify()
        self.assertEqual(self.counts(), (2, 0))

    def test_current_trust_or_crypto_failure_invalidates_warm_material(self):
        self.verify()
        self.failed = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.verify()
        self.assertEqual(list(self.session.glob('*.json')), [])
        self.failed = False
        self.verify()
        self.assertEqual(self.counts(), (2, 1))

    def test_live_identity_api_error_cannot_use_warm_material(self):
        self.verify()
        with patch.object(self, 'api', side_effect=RuntimeError('sanitized-api-failure')):
            with self.assertRaisesRegex(RuntimeError, 'api-failure'):
                self.verify()
        self.assertEqual(self.counts(), (1, 0))

    def test_nonregular_or_symlink_subject_never_uses_material(self):
        self.verify()
        original = self.root / 'original'
        self.subject.rename(original)
        self.subject.symlink_to(original)
        with self.assertRaises(OSError):
            self.verify()
        self.subject.unlink()
        os.mkfifo(self.subject)
        with self.assertRaisesRegex(ValueError, 'bounded attestation input'):
            self.verify()

    def test_cached_bundle_still_requires_cryptographic_verification(self):
        self.verify()
        entry = next(self.session.glob('*.json'))
        value = json.loads(entry.read_text())
        raw = base64.b64decode(value['material'])
        raw = raw.replace(b'"fixtureSignature":"valid"', b'"fixtureSignature":"forged"')
        value.update(material=base64.b64encode(raw).decode(), materialSha256=hashlib.sha256(raw).hexdigest())
        entry.write_text(json.dumps(value)); entry.chmod(0o600)
        with self.assertRaises(subprocess.CalledProcessError):
            self.verify()
        self.assertFalse(entry.exists())

    def test_swapped_file_during_verification_is_not_cached(self):
        self.mutate = True
        with self.assertRaisesRegex(ValueError, 'changed during verification'):
            self.verify()
        self.assertEqual(list(self.session.glob('*.json')), [])

    def test_digest_corruption_symlink_and_unsafe_modes_fail_closed(self):
        self.verify(); entry = next(self.session.glob('*.json'))
        value = json.loads(entry.read_text()); value['materialSha256'] = '0' * 64
        entry.write_text(json.dumps(value)); entry.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            self.verify()
        entry.unlink(); entry.symlink_to(self.subject)
        with self.assertRaises(OSError):
            self.verify()
        entry.unlink(); self.session.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'private attestation session'):
            self.verify()

    def test_repository_reassignment_during_verification_blocks(self):
        self.api_values = [{'full_name': REPO, 'id': 17, 'owner': {'login': 'closure-labs', 'id': 19}},
                           {'full_name': REPO, 'id': 18, 'owner': {'login': 'closure-labs', 'id': 19}}]
        with self.assertRaisesRegex(ValueError, 'repository changed'):
            self.verify()
        self.assertEqual(list(self.session.glob('*.json')), [])

    def test_unknown_or_wrong_producer_bundle_is_never_reused(self):
        self.output = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, 'subject differs'):
                self.verify()
        self.assertEqual(self.counts(), (2, 0))
        self.output = None; self.producer['runAttempt'] = 3
        self.verify(); self.verify()
        self.assertEqual(self.counts(), (4, 0))

    def test_publisher_session_discards_inherited_path_and_removes_material(self):
        inherited = os.environ[m.VARIABLE]
        with m.publisher_session():
            owned = Path(os.environ[m.VARIABLE])
            self.assertNotEqual(str(owned), inherited)
            (owned / 'private-material').write_bytes(b'public bundle fixture')
        self.assertFalse(owned.exists())
        self.assertEqual(os.environ[m.VARIABLE], inherited)

    def test_missing_session_preserves_online_path(self):
        os.environ.pop(m.VARIABLE)
        self.verify(); self.verify()
        self.assertEqual(self.counts(), (2, 0))
        self.assertEqual(self.api_calls, [])

    def gate(self, state):
        # Real gate control flow; only transport/ledger fixture acquisition is mocked.
        scan = {'revision': REV, 'producer': self.producer}
        def scanned(*args):
            self.verify()
            return scan
        def admitted(*args):
            if not state['approved']:
                raise authority.HumanDecisionRequired('Live approval revoked')
            return {'schema': 1, 'status': 'covered'}
        def ledger(*args, **kwargs):
            return (REV, {}, self.cfg) if kwargs.get('with_policy') else (REV, {})
        def api(endpoint):
            if '/rules/branches/' in endpoint:
                return [{'type': 'required_status_checks', 'parameters': {'required_status_checks': [
                    {'context': 'Maintainer decision authority', 'integration_id': 5384448}]}}]
            if '/compare/' in endpoint:
                return {'status': 'identical'}
            return {'object': {'sha': state['main']}}
        with patch.object(common, 'ledger', side_effect=ledger), patch.object(common, 'scans', side_effect=scanned), \
                patch.object(common, 'admission', side_effect=admitted), \
                patch.object(common, 'active_security', return_value=('fixture', {})):
            return common.gate(self.cfg, self.subject, api=api)

    def test_live_approval_revocation_blocks_with_warm_material(self):
        state = {'approved': True, 'main': REV}
        self.gate(state)
        state['approved'] = False
        with self.assertRaisesRegex(authority.HumanDecisionRequired, 'revoked'):
            self.gate(state)
        self.assertEqual(self.counts(), (1, 1))

    def test_live_main_change_blocks_with_warm_material(self):
        state = {'approved': True, 'main': REV}
        self.gate(state)
        state['main'] = 'c' * 40
        with self.assertRaisesRegex(ValueError, 'Protected main moved'):
            self.gate(state)
        self.assertEqual(self.counts(), (1, 1))

    def test_expired_evidence_is_rejected_before_cached_material(self):
        now = dt.datetime.now(dt.timezone.utc)
        value = {'schema': 1, 'repository': REPO, 'revision': REV, 'producer': self.producer,
                 'scannedAt': (now - dt.timedelta(minutes=1)).isoformat(),
                 'expiresAt': (now + dt.timedelta(seconds=10)).isoformat(),
                 'profiles': {'xo-latest': {'status': 'complete', 'scannerHealth': 'healthy',
                     'scannedAt': now.isoformat(), 'database': {'valid': True, 'built': now.isoformat()}}}}
        self.subject.write_text(json.dumps(value))
        caller = {'id': 7, 'run_attempt': 2, 'head_sha': REV, 'head_branch': 'main',
                  'event': 'push', 'path': WORKFLOW, 'status': 'completed', 'conclusion': 'success',
                  'repository': {'full_name': REPO}}
        def api(endpoint):
            return caller if '/actions/runs/' in endpoint else self.api(endpoint)
        original = dt.datetime
        class Later(original):
            @classmethod
            def now(cls, tz=None):
                return now + dt.timedelta(seconds=20)
        with patch.object(common, 'attestation_command', side_effect=self.command):
            common.scans(self.subject, self.cfg, api)
            with patch.object(common.dt, 'datetime', Later):
                with self.assertRaisesRegex(ValueError, 'Expired or future'):
                    common.scans(self.subject, self.cfg, api)
        self.assertEqual(self.counts(), (1, 0))


if __name__ == '__main__':
    unittest.main()
