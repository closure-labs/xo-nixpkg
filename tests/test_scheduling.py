# SPDX-License-Identifier: Apache-2.0
"""Scheduling is identity-bound data and never substitutes for authorization."""
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
import io

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'ci' if (ROOT / 'ci').is_dir() else ROOT / 'nix/automation'
sys.path.insert(0, str(FOLDER / 'decisions'))
import scheduling
import decision_packets as packets


class Scheduling(unittest.TestCase):
    def test_result_has_exact_identities_without_an_authority_claim(self):
        result = scheduling.result('owner/repo', 'a'*40, 'b'*40, 123, 2, 'wait', 'publication-active')
        self.assertFalse(result['authorityClaim'])
        self.assertEqual(result['producer'], {'runId': 123, 'runAttempt': 2})
        self.assertNotIn('command', result)
        with self.assertRaises(ValueError):
            scheduling.result('owner/repo', 'a'*40, 'b'*40, 123, 2, 'run shell', 'publication-active')

    def test_database_freshness_is_an_independent_earlier_deadline(self):
        now = dt.datetime.now(dt.timezone.utc)
        native = {'scannedAt': (now - dt.timedelta(hours=2)).isoformat(),
                  'expiresAt': (now + dt.timedelta(hours=20)).isoformat(),
                  'profiles': {'fixture': {'status':'complete', 'scannerHealth':'healthy',
                      'scannedAt': (now - dt.timedelta(hours=1)).isoformat(),
                      'database': {'valid':True, 'built':(now - dt.timedelta(hours=47)).isoformat()}}}}
        deadline = scheduling.observation_expiry(native, {'profiles':['fixture']})
        self.assertLess(deadline, now + dt.timedelta(hours=2))
        native['profiles']['fixture']['database']['built'] = (now - dt.timedelta(hours=49)).isoformat()
        self.assertLess(scheduling.observation_expiry(native, {'profiles':['fixture']}), now)

    def test_maestro_published_expiry_is_checked_before_suppressing_work(self):
        if FOLDER.name == 'ci':
            self.skipTest('Maestro retained selection contract')
        spec = importlib.util.spec_from_file_location('retained_scheduling', FOLDER / 'decision-retained.py')
        retained = importlib.util.module_from_spec(spec); spec.loader.exec_module(retained)
        producer = {'repository': 'owner/repo', 'revision': 'a'*40, 'sourceRevision': 'a'*40,
                    'runId': 123, 'runAttempt': 2}
        proposal = {'kind': 'release-product', 'payload': {'disposition': 'accepted', 'rationale': 'fixture', 'supersedes': [],
                    'product': {'revision': 'a'*40, 'assets': {'maestro-v1.2.3.iso.sha256': 'b'*64}},
                    'packet': {'reference': packets.REGISTRY + '@sha256:' + 'c'*64,
                               'sha256': 'd'*64, 'producer': producer}}}
        now = dt.datetime.now(dt.timezone.utc)
        scan = {'repository': 'owner/repo', 'revision': 'a'*40, 'producer': {'revision': 'a'*40, 'runId': 123, 'runAttempt': 2},
                'scannedAt': (now - dt.timedelta(hours=2)).isoformat(),
                'profiles': {'maestro': {'status': 'complete', 'scannerHealth': 'healthy',
                    'scannedAt': (now - dt.timedelta(hours=1)).isoformat(),
                    'database': {'valid': True, 'built': (now - dt.timedelta(hours=3)).isoformat()}}}}
        for hours, expected in [(1, {packets.canonical_hash(proposal['payload']['product'])}), (-1, set())]:
            scan['expiresAt'] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=hours)).isoformat()
            with patch.object(packets, 'metadata', return_value=scan):
                self.assertEqual(retained.current_published_products({'repository':'owner/repo', 'profiles':['maestro']}, {'p':proposal}, {'v1.2.3'}), expected)
        with patch.object(packets, 'metadata', side_effect=ValueError('metadata unavailable')):
            with self.assertRaises(ValueError):
                retained.current_published_products({'repository':'owner/repo', 'profiles':['maestro']}, {'p':proposal}, {'v1.2.3'})


if __name__ == '__main__':
    unittest.main()
