# SPDX-License-Identifier: Apache-2.0
"""Job-local immutable byte reuse cannot cache an authorization decision."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from test_packets import Registry, mod


class PacketReuse(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.registry = Registry()
        self.expected = mod.canonical_hash(self.registry.packet)
        self.env = mock.patch.dict(os.environ, {'RUNNER_TEMP': str(self.root), 'GITHUB_RUN_ID': '42',
                    'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_JOB': 'test'})
        self.env.start(); self.addCleanup(self.env.stop)
        self.command = mock.patch.object(mod, 'command', side_effect=self.registry.command).start()
        self.addCleanup(mock.patch.stopall)

    def fetch(self, name):
        return mod.fetch(self.registry.reference, self.root / name, self.expected)

    def test_duplicate_materialization_transfers_payload_once_and_rechecks_inventory(self):
        self.assertEqual(self.fetch('one'), self.registry.packet)
        initial = self.command.call_count
        self.assertGreater(initial, 1)
        self.command.reset_mock()
        self.assertEqual(self.fetch('two'), self.registry.packet)
        self.command.assert_not_called()
        left = self.root / 'one/finite/security-result.json'
        right = self.root / 'two/finite/security-result.json'
        self.assertEqual(left.stat().st_ino, right.stat().st_ino)
        self.assertEqual(left.read_bytes(), self.registry.data)
        # A consumer changing linked bytes invalidates all future reuse.
        left.write_bytes(b'changed payload')
        with self.assertRaisesRegex(ValueError, 'integrity'):
            self.fetch('three')
        self.command.assert_not_called()

    def test_attempt_or_verifier_changes_force_new_materialization(self):
        self.fetch('one')
        for name, environment in [('attempt', {'GITHUB_RUN_ATTEMPT': '3'}),
                                  ('job', {'GITHUB_JOB': 'other'})]:
            with mock.patch.dict(os.environ, environment):
                self.command.reset_mock(); self.fetch(name)
                self.assertGreater(self.command.call_count, 1)
        with mock.patch.object(mod, 'verifier_version', return_value='b' * 64):
            self.command.reset_mock(); self.fetch('verifier')
            self.assertGreater(self.command.call_count, 1)

    def test_symlinks_extra_files_and_producer_receipt_changes_block(self):
        self.fetch('one')
        cache = mod.job_cache(self.registry.reference, self.expected)
        receipt = cache / 'receipt.json'
        original = receipt.read_bytes()
        value = json.loads(original); value['producer'] = {'runId': 99}
        receipt.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'binding'):
            self.fetch('receipt')
        receipt.write_bytes(original)
        extra = cache / 'data/unexpected'; extra.write_text('unexpected')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            self.fetch('extra')
        extra.unlink(); extra.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'nonregular'):
            self.fetch('link')

    def test_cross_filesystem_output_preserves_the_existing_interface(self):
        import errno
        def cross_device(*args, **kwargs):
            raise OSError(errno.EXDEV, 'different filesystem')
        with mock.patch.object(mod.os, 'link', side_effect=cross_device):
            self.fetch('copied')
        self.assertEqual((self.root / 'copied/finite/security-result.json').read_bytes(), self.registry.data)

    def test_expired_budget_cannot_reuse_even_fully_verified_bytes(self):
        import time
        import subprocess
        self.fetch('one'); self.command.reset_mock()
        with mod.operations.budget(.001):
            time.sleep(.005)
            with self.assertRaises(subprocess.TimeoutExpired):
                self.fetch('expired')
        self.command.assert_not_called()

    def test_metadata_read_avoids_unrequested_payload(self):
        self.registry.data = b'{"expiresAt":"2099-01-01T00:00:00Z"}'
        self.registry.packet['files']['finite/security-result.json'] = {
            'size': len(self.registry.data), 'sha256': __import__('hashlib').sha256(self.registry.data).hexdigest()}
        self.registry.packet_bytes = json.dumps(self.registry.packet).encode()
        self.registry.layers[:] = [self.registry.layer('decision-packet.json', self.registry.packet_bytes),
                                    self.registry.layer('finite/security-result.json', self.registry.data)]
        self.registry.blobs = {__import__('hashlib').sha256(value).hexdigest(): value
                               for value in (self.registry.packet_bytes, self.registry.data)}
        self.registry.refresh()
        value = mod.metadata(self.registry.reference, mod.canonical_hash(self.registry.packet), 'finite/security-result.json')
        self.assertEqual(value['expiresAt'], '2099-01-01T00:00:00Z')
        self.assertEqual(self.command.call_count, 3)  # manifest, descriptor, requested metadata only


if __name__ == '__main__':
    unittest.main()
