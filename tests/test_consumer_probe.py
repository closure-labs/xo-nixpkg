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
        copy, verify, metadata = self.calls
        store = copy[copy.index('--to') + 1]
        self.assertTrue(store.startswith('local?root='))
        self.assertFalse(Path(store.removeprefix('local?root=')).exists())
        self.assertEqual(verify[verify.index('--store') + 1], store)
        self.assertIn('--recursive', verify)
        self.assertEqual(verify[verify.index('--sigs-needed') + 1], '1')
        self.assertNotIn('--no-check-sigs', copy)
        self.assertEqual(copy[-1], PATH)
        self.assertEqual(metadata[-1], PATH)

    def test_hash_mismatch_blocks(self):
        self.observed = 'sha256-' + 'B' * 43 + '='
        with self.assertRaises(ValueError):
            probe.probe(PRODUCT, 'https://cache.example', 'cache-key', self.execute)

    def test_download_or_signature_failure_blocks(self):
        for operation in ('copy', 'verify'):
            self.failure = operation
            with self.assertRaises(subprocess.CalledProcessError):
                probe.probe(PRODUCT, 'https://cache.example', 'cache-key', self.execute)


if __name__ == '__main__':
    unittest.main()
