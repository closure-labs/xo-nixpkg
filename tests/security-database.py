#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot integrity and scanner integration, with deterministic native boundaries."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('database', ROOT / 'ci/security-database.py')
database = importlib.util.module_from_spec(spec)
spec.loader.exec_module(database)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'snapshot'
        self.updates = 0
        self.status = {'valid': True, 'schemaVersion': 'v6.1.10', 'built': database.now().isoformat()}
        self.addCleanup(patch.stopall)
        patch.object(database.subprocess, 'run', self.fake_run).start()
        patch.object(database.subprocess, 'check_output', self.output).start()

    def fake_run(self, command, **kwargs):
        self.assertEqual(command[-2:], ['db', 'update'])
        self.assertNotIn('GRYPE_CONFIG', kwargs['env'])
        self.assertNotIn('GRYPE_DB_UPDATE_URL', kwargs['env'])
        db = Path(kwargs['env']['GRYPE_DB_CACHE_DIR']) / '6'
        db.mkdir(parents=True)
        (db / 'vulnerability.db').write_bytes(b'authenticated online fixture bytes')
        self.updates += 1

    def output(self, command, **kwargs):
        if 'version' in command:
            return json.dumps({'version': 'native-fixture'})
        self.assertEqual(command[-4:], ['db', 'status', '-o', 'json'])
        return json.dumps(self.status)

    def prepare(self):
        with patch.dict(os.environ, {'GRYPE_CONFIG': '/poison', 'GRYPE_DB_UPDATE_URL': 'https://poison.invalid'}):
            return database.prepare(self.root)

    def rewrite(self, change):
        path = self.root / 'receipt.json'
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_four_profiles_share_one_online_preparation(self):
        digest = self.prepare()
        for _ in range(4):
            database.verify(self.root, digest)
        self.assertEqual(self.updates, 1)

    def test_bad_anchor_and_mutated_bytes_rejected(self):
        digest = self.prepare()
        with self.assertRaises(ValueError): database.verify(self.root, '0' * 64)
        (self.root / 'db/6/vulnerability.db').write_bytes(b'poison')
        with self.assertRaises(ValueError): database.verify(self.root, digest)

    def test_config_override_and_symlink_rejected(self):
        digest = self.prepare()
        (self.root / 'grype.yaml').write_text('db:\n  update-url: https://poison.invalid\n')
        with self.assertRaises(ValueError): database.verify(self.root, digest)
        (self.root / 'grype.yaml').write_text('{}\n')
        (self.root / 'db/link').symlink_to('/etc/passwd')
        with self.assertRaises(ValueError): database.verify(self.root, digest)

    def test_stale_future_database_and_schema_rejected(self):
        digest = self.prepare()
        for status in [dict(self.status, built=(database.now()-dt.timedelta(hours=49)).isoformat()),
                       dict(self.status, built=(database.now()+dt.timedelta(hours=1)).isoformat()),
                       dict(self.status, schemaVersion='unknown'), dict(self.status, valid=False)]:
            self.status = status
            with self.assertRaises(ValueError): database.verify(self.root, digest)

    def test_stale_future_preparation_and_unchecked_receipt_rejected(self):
        self.prepare()
        for offset in [-5, 1]:
            digest = self.rewrite(lambda v: v.update(preparedAt=(database.now()+dt.timedelta(hours=offset)).isoformat()))
            with self.assertRaises(ValueError): database.verify(self.root, digest)
        digest = self.rewrite(lambda v: v.update(preparedAt=database.now().isoformat(), onlineUpdate=False))
        with self.assertRaises(ValueError): database.verify(self.root, digest)

    def test_prepare_requires_empty_directory_and_online_success(self):
        self.prepare()
        with self.assertRaises(ValueError): self.prepare()
        with patch.object(database.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'grype')):
            with self.assertRaises(subprocess.CalledProcessError): database.prepare(Path(self.temp.name)/'failed')
        self.assertFalse((Path(self.temp.name)/'failed/receipt.json').exists())


class ScannerTests(unittest.TestCase):
    def test_shared_snapshot_runs_each_probe_and_rejects_mutation(self):
        with tempfile.TemporaryDirectory() as name:
            temp = Path(name)
            binpath = temp / 'bin'; binpath.mkdir()
            (temp/'inventory').mkdir(); (temp/'inventory/runtime.cdx.json').write_text('{}')
            fake = '''#!/usr/bin/env python3
import os,json,sys,datetime
from pathlib import Path
args=sys.argv[1:]; root=Path(os.environ['GRYPE_DB_CACHE_DIR'])
with open(os.environ['CALLS'],'a') as log: log.write(json.dumps(args)+'\\n')
if args[-2:]==['db','update']:
 root.mkdir(parents=True);(root/'vulnerability.db').write_text('native bytes')
elif 'version' in args: print('{"version":"fixture"}')
elif 'status' in args: print(json.dumps({'valid':True,'built':os.environ['BUILT'],'schemaVersion':'v6.1.10'}))
else:
 assert os.environ['GRYPE_DB_AUTO_UPDATE']=='false'
 if os.environ.get('MUTATE')=='true' and any('runtime.cdx.json' in a for a in args): (root/'vulnerability.db').write_text('tampered')
 matches=[{'artifact':{'name':'openssl'}},{'artifact':{'name':'lodash'}}]
 if os.environ.get('MISSING_JS')=='true': matches=matches[:1]
 print(json.dumps({'matches':matches}))
'''
            (binpath/'grype').write_text(fake.replace('#!/usr/bin/env python3', '#!' + sys.executable, 1)); (binpath/'grype').chmod(0o755)
            helper=binpath/'xo-nixpkg-security-database'
            helper.write_text('#!/bin/sh\nexec python3 '+str(ROOT/'ci/security-database.py')+' "$@"\n');helper.chmod(0o755)
            normalizer=temp/'normalize.py';normalizer.write_text("import pathlib,sys\npathlib.Path(sys.argv[2],'scan.json').write_text('{}')\n")
            env=dict(os.environ,PATH=str(binpath)+os.pathsep+os.environ['PATH'],CALLS=str(temp/'calls'),BUILT=database.now().isoformat(),XO_NIXPKG_SECURITY_NORMALIZER=str(normalizer),GRYPE_CONFIG='/poison',GRYPE_DB_UPDATE_URL='https://poison.invalid')
            digest=subprocess.check_output([str(helper),'prepare',str(temp/'prepared')],env=env,text=True).strip()
            for i in range(4):
                subprocess.run(['bash',str(ROOT/'ci/security-native-scan.sh'),str(temp/'inventory'),str(temp/str(i)),'--database',str(temp/'prepared'),'--database-receipt-sha256',digest],env=env,check=True)
                status=json.loads((temp/str(i)/'database.json').read_text());self.assertEqual(status['snapshotReceiptSha256'],digest)
            calls=[json.loads(x) for x in (temp/'calls').read_text().splitlines()]
            self.assertEqual(sum(c[-2:]==['db','update'] for c in calls),1)
            self.assertEqual(sum(any('probe.json' in a for a in c) for c in calls),4)
            subprocess.run(['bash',str(ROOT/'ci/security-native-scan.sh'),str(temp/'inventory'),str(temp/'standalone')],env=env,check=True)
            calls=[json.loads(x) for x in (temp/'calls').read_text().splitlines()]
            self.assertEqual(sum(c[-2:]==['db','update'] for c in calls),2)
            self.assertEqual(sum(any('probe.json' in a for a in c) for c in calls),5)
            for problem in ('MISSING_JS','MUTATE'):
                output=temp/problem;output.mkdir();(output/'scan.json').write_text('old success')
                result=subprocess.run(['bash',str(ROOT/'ci/security-native-scan.sh'),str(temp/'inventory'),str(output),'--database',str(temp/'prepared'),'--database-receipt-sha256',digest],env=dict(env,**{problem:'true'}),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                self.assertNotEqual(result.returncode,0);self.assertFalse((output/'scan.json').exists())


if __name__ == '__main__':
    unittest.main()
