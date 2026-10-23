#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retain the exact admitted product checked by the hosted consumer."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'ci' if (ROOT / 'ci').is_dir() else ROOT / 'nix/automation'
sys.path.insert(0, str(FOLDER / 'decisions'))
SPEC = importlib.util.spec_from_file_location('consumer_result_probe', FOLDER / 'consumer-probe.py')
consumer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(consumer)


def proposal(run):
    return {'kind': 'release-product', 'payload': {
        'disposition': 'accepted', 'product': {'fixture': run},
        'packet': {'producer': {'runId': run, 'runAttempt': 1}}}}


class ConsumerResult(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.old, self.selected = proposal(10), proposal(20)
        self.result = {'schema': 1, 'status': 'verified', 'roots': 8,
                       'productHash': consumer.common.canonical_hash(self.selected['payload']['product']),
                       'downloadedBytesVerified': True, 'signaturesVerified': True}
        self.artifact = Path(self.temporary.name) / 'public-consumer-result.json'
        patches = [
            patch.dict(os.environ, {'RUNNER_TEMP': self.temporary.name}),
            patch.object(sys, 'argv', ['consumer', '--config', 'fixture',
                                      '--cache', 'https://cache.example', '--key', 'public']),
            patch.object(consumer.common, 'config', return_value={}),
            patch.object(consumer.common, 'ledger', return_value=(
                'main', {'old': self.old, 'selected': self.selected})),
            patch.object(consumer.common, 'active_release', side_effect=lambda cfg, records, product, authenticate:
                         (None, self.old if product == self.old['payload']['product'] else self.selected)),
        ]
        for pending in patches:
            pending.start()
            self.addCleanup(pending.stop)
        provenance = patch.object(consumer.common, 'historical_provenance')
        self.provenance = provenance.start()
        self.addCleanup(provenance.stop)
        probe = patch.object(consumer, 'probe', return_value=copy.deepcopy(self.result))
        self.probe = probe.start()
        self.addCleanup(probe.stop)

    def invoke(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            consumer.main()
        return json.loads(output.getvalue())

    def test_hosted_result_identifies_the_exact_selected_product(self):
        result = self.invoke()
        self.assertEqual(json.loads(self.artifact.read_text()), result)
        self.assertEqual(result, dict(self.result, proposalHash=consumer.common.canonical_hash(self.selected)))
        self.probe.assert_called_once_with(self.selected['payload']['product'], 'https://cache.example', 'public')
        self.assertEqual(self.provenance.call_count, 2)

    def test_local_result_remains_available_on_stdout(self):
        with patch.dict(os.environ, {'RUNNER_TEMP': ''}):
            result = self.invoke()
        self.assertEqual(result['proposalHash'], consumer.common.canonical_hash(self.selected))
        self.assertFalse(self.artifact.exists())

    def test_failed_probe_does_not_retain_a_verified_result(self):
        self.probe.side_effect = ValueError('signature failure')
        with self.assertRaisesRegex(ValueError, 'signature failure'):
            self.invoke()
        self.assertFalse(self.artifact.exists())


if __name__ == '__main__':
    unittest.main()
