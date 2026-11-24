# SPDX-License-Identifier: Apache-2.0
"""Explain metadata fallback without weakening exact scan-producer selection."""
import contextlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci/decisions'))
spec = importlib.util.spec_from_file_location('publication_fetch_source', ROOT / 'ci/fetch-retained.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class PublicationFetchSource(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / 'evidence'
        self.artifact = self.root / 'publication-fetch-source.json'
        registry = 'ghcr.io/closure-labs/xo-nixpkg-decisions'
        for name, value in [('REGISTRY', registry), ('REFERENCE', re.compile(re.escape(registry) + r'@sha256:[0-9a-f]{64}'))]:
            setting = patch.object(m.packets, name, value)
            setting.start()
            self.addCleanup(setting.stop)
        self.packet = {'reference': registry + '@sha256:' + 'a' * 64,
                       'sha256': 'b' * 64, 'producer': {'repository': 'closure-labs/xo-nixpkg',
                       'runId': 123, 'runAttempt': 2}}
        self.environment = patch.dict(os.environ, {'RUNNER_TEMP': str(self.root),
            'QUALIFICATION_RUN': '123', 'QUALIFICATION_ATTEMPT': '2',
            'XO_NIXPKG_EVIDENCE': str(self.output), 'XO_NIXPKG_PUBLICATION_METADATA_ONLY': 'true'})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def execute(self, packets, *, metadata_error=None, config_error=None):
        with patch.object(m, 'config', return_value={}, side_effect=config_error), \
                patch.object(m, 'find_packets', return_value=packets), \
                patch.object(m.packets, 'metadata_bytes', return_value=b'{}', side_effect=metadata_error) as metadata:
            m.main()
        return metadata

    def test_exact_source_fetches_metadata_only_and_retains_fixed_diagnostics(self):
        metadata = self.execute([self.packet])
        self.assertEqual([c.args[2] for c in metadata.call_args_list], ['product.json', 'scans.json'])
        self.assertEqual(set(p.name for p in self.output.iterdir()), {'product.json', 'scans.json'})
        self.assertEqual(json.loads(self.output.with_suffix('.source.json').read_text()), self.packet)
        value = json.loads(self.artifact.read_text())
        self.assertEqual(value['status'], 'exact-packet')
        self.assertFalse(value['authorityClaim'])
        self.assertEqual(set(value), {'schema', 'authorityClaim', 'status', 'elapsedMilliseconds',
                                     'discoveryMilliseconds', 'metadataMilliseconds'})
        self.assertGreaterEqual(value['elapsedMilliseconds'], value['discoveryMilliseconds'] + value['metadataMilliseconds'])
        self.assertNotIn('reference', self.artifact.read_text())

    def test_no_full_packet_does_not_misreport_live_artifact_as_expired(self):
        with patch.dict(os.environ, {'XO_NIXPKG_PUBLICATION_METADATA_ONLY': 'false'}):
            with self.assertRaisesRegex(ValueError, 'no retained immutable decision packet') as error:
                self.execute([])
        self.assertNotIn('expired', str(error.exception))
        self.assertFalse(self.output.exists())

    def test_no_exact_source_keeps_exit_four_and_no_materialization(self):
        with self.assertRaises(SystemExit) as error:
            self.execute([])
        self.assertEqual(error.exception.code, 4)
        self.assertFalse(self.output.exists())
        self.assertEqual(json.loads(self.artifact.read_text())['status'], 'no-exact-packet')

    def test_ambiguity_and_validation_failure_do_not_become_fallback(self):
        for packets, message, kwargs, status in [
                ([self.packet, self.packet], 'Ambiguous', {}, 'ambiguous-exact-packets'),
                ([self.packet], 'PRIVATE_TOKEN', {'metadata_error': ValueError('PRIVATE_TOKEN /private/path')}, 'blocked'),
                ([], 'PRIVATE_POLICY', {'config_error': ValueError('PRIVATE_POLICY')}, 'blocked')]:
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, message):
                self.execute(packets, **kwargs)
            self.assertEqual(json.loads(self.artifact.read_text())['status'], status)
            self.assertNotIn('PRIVATE', self.artifact.read_text())
            self.assertNotIn('/private/path', self.artifact.read_text())
            self.assertFalse(self.output.exists())

    def test_diagnostic_symlink_is_replaced_without_touching_target(self):
        target = self.root / 'target'
        target.write_text('unchanged')
        self.artifact.symlink_to(target)
        self.execute([self.packet])
        self.assertEqual(target.read_text(), 'unchanged')
        self.assertFalse(self.artifact.is_symlink())

    def test_diagnostic_failure_preserves_original_exit_and_does_not_leak_error(self):
        with patch.object(m.tempfile, 'NamedTemporaryFile', side_effect=OSError('PRIVATE_TOKEN')), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as error:
                self.execute([])
        self.assertEqual(error.exception.code, 4)
        self.assertNotIn('PRIVATE_TOKEN', stderr.getvalue())

    def test_discovery_does_not_substitute_older_run_or_attempt(self):
        repository = self.packet['producer']['repository']
        for producer in [dict(self.packet['producer'], runId=122),
                         dict(self.packet['producer'], runAttempt=1), self.packet['producer']]:
            packet = dict(self.packet, producer=producer)
            import common
            with patch.object(common, 'ledger', return_value=('d' * 40, {
                    'c' * 64: {'payload': {'packet': packet}}})):
                found = m.find_packets({'repository': repository}, 123, 2)
            self.assertEqual(found, [packet] if producer == self.packet['producer'] else [])

    def test_native_retry_discovers_exact_public_handoff_without_reading_the_old_ledger(self):
        import base64
        import common
        import hashlib
        from test_native_approvals import cfg, request
        policy, approved = cfg(), request()
        raw = json.dumps(approved).encode()
        metadata = {'type': 'file', 'encoding': 'base64', 'size': len(raw),
                    'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                    'content': base64.b64encode(raw).decode()}
        packet = dict(self.packet, reference='ghcr.io/closure-labs/xo-nixpkg-products@sha256:' + 'a' * 64)
        receipt = {'schema': 1, 'destination': 'handoff', 'productHash': approved['productHash'],
                   'status': 'verified', 'expected': packet, 'observed': packet,
                   'verifiedAt': '2026-11-24T00:00:00Z', 'verifier': 'f' * 64}
        journal = {'schema': 2, 'productHash': approved['productHash'], 'receipts': {'handoff': receipt},
                   'steps': [{'name': 'handoff', 'state': 'complete', 'identity': packet}]}
        ref = {'object': {'type': 'commit', 'sha': 'e' * 40}}
        with patch.object(m, 'optional_metadata', side_effect=[metadata, ref]), \
                patch.object(m.authority, 'github_api', return_value={'object': {'sha': 'd' * 40}}), \
                patch.object(m.authority, 'document_at', return_value=journal), \
                patch.object(common, 'ledger', side_effect=AssertionError('retired ledger')):
            self.assertEqual(m.find_packets(policy, 123, 2), [packet])
        self.assertEqual(m.packets.REGISTRY, 'ghcr.io/closure-labs/xo-nixpkg-products')

    def test_optional_native_transport_metadata_never_treats_denial_as_absence(self):
        import subprocess
        for code in (403, 429, 500):
            value = subprocess.CompletedProcess([], 1, '', 'gh: request failed (HTTP ' + str(code) + ')')
            with patch.object(m.subprocess, 'run', return_value=value), self.assertRaisesRegex(ValueError, 'unavailable'):
                m.optional_metadata('fixed-repository-endpoint')
        value = subprocess.CompletedProcess([], 1, '', 'gh: Not Found (HTTP 404)')
        with patch.object(m.subprocess, 'run', return_value=value):
            self.assertIsNone(m.optional_metadata('fixed-repository-endpoint'))

    def test_first_native_publication_never_needs_the_retired_ledger(self):
        import common
        from test_native_approvals import cfg
        with patch.object(m, 'published_packet', return_value=None), \
                patch.object(common, 'ledger', side_effect=AssertionError('retired ledger')):
            self.assertEqual(m.find_packets(cfg(), 123, 2), [])


if __name__ == '__main__':
    unittest.main()
