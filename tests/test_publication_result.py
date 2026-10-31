#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retain actual publication branches, never infer transfers from a journal."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('publication_result_controller', ROOT / 'ci/publication-controller.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
import decision_packets as packets


class PublicationResult(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / 'evidence'
        self.directory.mkdir()
        self.product = {'repository':'closure-labs/xo-nixpkg','revision':'a'*40,
                        'products':{'root':{'storePath':'/nix/store/'+'1'*32+'-root','narHash':'sha256-fixture'}},
                        'assets':{}}
        self.producer = {'repository':self.product['repository'],'revision':'a'*40,
                         'sourceRevision':'a'*40,'workflow':'.github/workflows/qualification.yml',
                         'runId':123,'runAttempt':1}
        self.scans = {'producer':self.producer}
        self.source = {'reference':'ghcr.io/closure-labs/xo-nixpkg-decisions@sha256:'+'d'*64,
                       'sha256':'e'*64,'producer':self.producer}
        files = {}
        for name, value in [('product.json',self.product),('scans.json',self.scans)]:
            raw = json.dumps(value).encode(); (self.directory/name).write_bytes(raw)
            files[name] = {'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)}
        self.directory.with_suffix('.source.json').write_text(json.dumps(self.source))
        self.descriptor = {'files':files,'producer':self.producer}
        self.artifact = self.root/'publication-result.json'
        self.calls = []
        class Journal:
            def __init__(self, repository, product, authorize):
                self.digest = hashlib.sha256(m.canonical(product)).hexdigest()
                self.branch = 'automation/publication-'+self.digest
                self.save_attempts = 0
                self.authorize = authorize
            def complete(self, *args):
                self.authorize()
        self.journal = Journal
        self.environment = patch.dict(os.environ, {'RUNNER_TEMP':str(self.root),
            'XO_NIXPKG_EVIDENCE':str(self.directory),'XO_NIXPKG_CACHIX_CACHE_URL':'https://fixture.invalid',
            'XO_NIXPKG_PUBLICATION_PURPOSE':'release','GITHUB_REPOSITORY':self.product['repository']})
        self.environment.start(); self.addCleanup(self.environment.stop)

    def output(self, args, **kwargs):
        if args[:2] == ['git','rev-parse']: return 'b'*40+'\n'
        if args[-1].endswith(':VERSION'): return '0.10.1\n'
        return json.dumps({'channels':{'latest':{'version':'6.9.1','rev':'c'*40}}})

    def execute(self, args=(), fail=False, fail_handoff=False):
        def run(*args, **kwargs):
            self.calls.append(args)
            if fail: raise subprocess.CalledProcessError(27,args)
        cache = {'status':'verified','expected':{'root':'hash'},'observed':{'root':'hash'}}
        states = [dict(cache,status='partial'),cache] if args else [cache]
        with patch.object(m,'Journal',self.journal), patch.object(m,'run',side_effect=run), \
                patch.object(m,'source_descriptor',return_value=self.descriptor), \
                patch.object(m.destinations,'cache',side_effect=states), \
                patch.object(m.destinations,'receipt',side_effect=lambda state,product:state), \
                patch.object(m,'remote_handoff',return_value=self.source, side_effect=RuntimeError('PRIVATE_TOKEN /private/path') if fail_handoff else None), \
                patch.object(m,'registry',contextlib.nullcontext), \
                patch.object(packets,'fetch',side_effect=lambda ref,target,digest:(target.mkdir(),(target/'decision-packet.json').write_text('{}'))), \
                patch.object(m.subprocess,'check_output',side_effect=self.output), \
                patch.object(m.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'f'*40+'\n','')), \
                contextlib.redirect_stdout(io.StringIO()):
            m.main()
        return json.loads(self.artifact.read_text())

    def test_noop_retains_exact_product_and_zero_transfer_branches(self):
        result = self.execute()
        self.assertEqual(result['productHash'],hashlib.sha256(m.canonical(self.product)).hexdigest())
        self.assertEqual(result['sourceRevision'],self.product['revision'])
        self.assertEqual(result['producer'],self.producer)
        self.assertTrue(result['metadataSourceAvailable'])
        self.assertEqual(result['status'],'verified')
        self.assertEqual(result['operations'],dict(closurePacketFetches=0,cachePublishInvocations=0,
            handoffCopyAttempts=0,handoffPushInvocations=0,xoTagLeafInvocations=1,projectTagInvocations=0,
            releasePublishInvocations=0,xoTagRequired=False,journalSaveAttempts=0))
        self.assertNotIn(('xo-nixpkg-publish',),self.calls)
        self.assertEqual(self.calls.count(('xo-nixpkg-publication-gate',)),4)

    def test_cache_repair_records_fetch_and_publication_instead_of_noop(self):
        result = self.execute(args=('repair',))
        self.assertEqual(result['operations']['closurePacketFetches'],1)
        self.assertEqual(result['operations']['cachePublishInvocations'],1)
        self.assertIn(('xo-nixpkg-publish',),self.calls)

    def test_failed_live_gate_replaces_stale_success_with_non_authoritative_summary(self):
        self.artifact.write_text('{"status":"verified"}')
        with self.assertRaises(subprocess.CalledProcessError): self.execute(fail=True)
        partial = json.loads(self.artifact.read_text())
        self.assertEqual(partial['status'], 'incomplete')
        self.assertFalse(partial['authorityClaim'])
        self.assertEqual(partial['failedStage'], 'admission')
        self.assertEqual(partial['completedStages'], [])
        self.assertNotIn('productHash', partial)

    def test_partial_cache_checkpoint_is_distinguished_from_handoff_attempt(self):
        with self.assertRaises(RuntimeError): self.execute(fail_handoff=True)
        partial = json.loads(self.artifact.read_text())
        self.assertEqual(partial['status'], 'incomplete')
        self.assertEqual(partial['failedStage'], 'handoff')
        self.assertEqual(partial['completedStages'], ['cache'])
        self.assertFalse(partial['authorityClaim'])
        self.assertNotIn('PRIVATE_TOKEN', self.artifact.read_text())
        self.assertNotIn('/private/path', self.artifact.read_text())


    def test_handoff_observation_records_copy_before_execution_only_if_missing(self):
        for missing in (False,True):
            with self.subTest(missing=missing):
                observations = {'handoffCopyAttempts':0}
                calls = []
                def command(args, **kwargs):
                    calls.append(args)
                    if args[:2] == ['oras','copy']:
                        self.assertEqual(observations['handoffCopyAttempts'],1)
                        raise RuntimeError('copy interrupted')
                    return None if missing else b'present'
                with patch.dict(os.environ,{'GITHUB_REPOSITORY':self.product['repository']}), \
                        patch.object(m,'registry',contextlib.nullcontext), \
                        patch.object(m,'run'), patch.object(packets,'command',side_effect=command), \
                        patch.object(packets,'inspect',return_value=({},{})), \
                        patch.object(packets,'fetch_member'), patch.object(packets,'packet_descriptor',return_value=self.descriptor):
                    if missing:
                        with self.assertRaisesRegex(RuntimeError,'interrupted'):
                            m.remote_handoff(self.source,self.descriptor,observations)
                    else:
                        m.remote_handoff(self.source,self.descriptor,observations)
                self.assertEqual(observations['handoffCopyAttempts'],int(missing))
                self.assertEqual(sum(c[:2]==['oras','copy'] for c in calls),int(missing))

    def test_journal_save_attempt_is_counted_before_revoked_authority(self):
        journal = object.__new__(m.Journal)
        journal.save_attempts = 0
        journal.authorize = lambda: (_ for _ in ()).throw(ValueError('revoked'))
        with patch.object(m,'api') as api, self.assertRaisesRegex(ValueError,'revoked'):
            journal.save()
        self.assertEqual(journal.save_attempts,1)
        api.assert_not_called()


if __name__ == '__main__':
    unittest.main()
