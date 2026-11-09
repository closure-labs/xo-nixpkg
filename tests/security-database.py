#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot integrity and scanner integration, with deterministic native boundaries."""
import datetime as dt
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
spec = importlib.util.spec_from_file_location('database', ROOT / 'ci/security-database.py')
database = importlib.util.module_from_spec(spec)
spec.loader.exec_module(database)


class SnapshotFixture(unittest.TestCase):
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



class SnapshotTests(SnapshotFixture):
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


class PreparationDiagnosticsTests(SnapshotFixture):
    def setUp(self):
        super().setUp()
        self.clock = dt.datetime(2026, 11, 9, 18, tzinfo=dt.timezone.utc)
        patch.object(database, 'now', return_value=self.clock).start()
        patch.object(database.sys, 'stderr', new_callable=io.StringIO).start()
        self.sleep = patch.object(database.time, 'sleep').start()
        self.status['built'] = (self.clock - dt.timedelta(hours=1)).isoformat()
        self.report = Path(self.temp.name) / 'report/database-preparation.json'

    def prepare_report(self):
        return database.prepare(self.root, 24, self.report)

    def read_report(self):
        return json.loads(self.report.read_text())

    def test_stale_future_and_invalid_status_retain_safe_diagnostics_without_retry(self):
        original = dict(self.status, path='secret-path', error='secret-error')
        for index, (change, reason) in enumerate([
            ({'built': (self.clock-dt.timedelta(hours=36)).isoformat()}, 'stale'),
            ({'built': (self.clock+dt.timedelta(hours=1)).isoformat()}, 'future_dated'),
            ({'schemaVersion': 'secret-schema'}, 'invalid_status'),
            ({'valid': False}, 'invalid_status'),
            ({'built': 'secret-timestamp'}, 'invalid_timestamp'),
        ]):
            with self.subTest(reason=reason):
                self.root = Path(self.temp.name) / str(index)
                self.status = dict(original, **change)
                with self.assertRaises(ValueError): self.prepare_report()
                value = self.read_report()
                self.assertEqual(value['result'], 'failed')
                self.assertEqual(value['database']['reason'], reason)
                self.assertEqual(value['database']['maximumAgeHours'], 24)
                self.assertEqual(value['updates'], [{'exitCode': 0}])
                self.assertFalse((self.root/'receipt.json').exists())
                self.assertNotIn('secret-', self.report.read_text())
                if index == 0:
                    self.assertEqual(value['database']['checkedAt'], self.clock.isoformat())
                    self.assertEqual(value['database']['ageHours'], 36)
                    self.assertEqual(value['database']['builtAt'], '2026-11-08T06:00:00+00:00')
                    self.assertEqual(value['database']['schemaVersion'], 'v6.1.10')
        self.assertEqual(self.updates, 5)
        self.sleep.assert_not_called()

    def test_exact_age_boundary_and_future_microsecond(self):
        for age in (dt.timedelta(hours=24), dt.timedelta(0)):
            status = dict(self.status, built=(self.clock-age).isoformat())
            database.validate_status(status, 24)
        for age in (dt.timedelta(hours=24, microseconds=1), dt.timedelta(microseconds=-1)):
            with self.assertRaises(ValueError):
                database.validate_status(dict(self.status, built=(self.clock-age).isoformat()), 24)

    def test_transient_update_recovers_once_and_receipt_verifies(self):
        calls = []
        def update(command, **kwargs):
            calls.append(command)
            if len(calls) == 1:
                raise subprocess.CalledProcessError(1, command, stderr='response code: 503 secret-url')
            return self.fake_run(command, **kwargs)
        with patch.object(database.subprocess, 'run', side_effect=update):
            digest = self.prepare_report()
        self.assertEqual(len(calls), 2)
        self.sleep.assert_called_once_with(5)
        database.verify(self.root, digest, 24)
        value = self.read_report()
        self.assertEqual(value['result'], 'prepared')
        self.assertEqual(value['updates'], [{'exitCode': 1, 'transient': True}, {'exitCode': 0}])
        self.assertNotIn('secret-', self.report.read_text())

    def test_update_retry_is_bounded_and_permanent_errors_are_not_retried(self):
        for index, (message, attempts) in enumerate([
            ('i/o timeout secret-url', 2), ('response code: 503', 2),
            ('response code: 401 secret-url', 1), ('response code: 403 secret-url', 1),
            ('x509: certificate signed by unknown authority', 1), ('checksum mismatch', 1),
        ]):
            with self.subTest(message=message):
                self.root = Path(self.temp.name) / str(index)
                error = subprocess.CalledProcessError(1, 'grype', stderr=message)
                with patch.object(database.subprocess, 'run', side_effect=error) as update:
                    with self.assertRaises(subprocess.CalledProcessError): self.prepare_report()
                self.assertEqual(update.call_count, attempts)
                value = self.read_report()
                self.assertEqual(value['result'], 'failed')
                self.assertEqual(value['stage'], 'update')
                self.assertEqual(len(value['updates']), attempts)
                self.assertFalse((self.root/'receipt.json').exists())
                self.assertNotIn('secret-', self.report.read_text())

    def test_recovered_update_still_rejects_stale_database(self):
        calls = []
        def update(command, **kwargs):
            calls.append(command)
            if len(calls) == 1:
                raise subprocess.CalledProcessError(1, command, stderr='connection reset by peer')
            return self.fake_run(command, **kwargs)
        self.status['built'] = (self.clock-dt.timedelta(hours=36)).isoformat()
        with patch.object(database.subprocess, 'run', side_effect=update):
            with self.assertRaises(ValueError): self.prepare_report()
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.read_report()['database']['reason'], 'stale')
        self.assertFalse((self.root/'receipt.json').exists())

    def test_status_command_and_json_failures_never_create_receipt(self):
        for index, output in enumerate([json.dumps(self.status), 'secret-malformed-json', None]):
            self.root = Path(self.temp.name) / ('command-' + str(index))
            error = subprocess.CalledProcessError(1, 'grype', output=output)
            with patch.object(database.subprocess, 'check_output', side_effect=error):
                with self.assertRaises(subprocess.CalledProcessError): self.prepare_report()
            value = self.read_report()
            self.assertEqual(value['statusExitCode'], 1)
            self.assertEqual(value['result'], 'failed')
            self.assertEqual(value['stage'], 'status')
            self.assertFalse((self.root/'receipt.json').exists())
            self.assertNotIn('secret-', self.report.read_text())
            if index == 0:
                self.assertEqual(value['database']['ageHours'], 1)
        for index, output in enumerate(['secret-malformed-json', '[]', '{"valid":true}']):
            self.root = Path(self.temp.name) / ('json-' + str(index))
            with patch.object(database.subprocess, 'check_output', return_value=output):
                with self.assertRaises(ValueError): self.prepare_report()
            self.assertEqual(self.read_report()['result'], 'failed')
            self.assertFalse((self.root/'receipt.json').exists())
            self.assertNotIn('secret-', self.report.read_text())

    def test_atomic_diagnostics_replace_symlink_without_touching_target(self):
        target = Path(self.temp.name)/'do-not-change'
        target.write_text('original')
        self.report.parent.mkdir()
        self.report.symlink_to(target)
        digest = self.prepare_report()
        self.assertEqual(target.read_text(), 'original')
        self.assertFalse(self.report.is_symlink())
        self.assertEqual(self.read_report()['result'], 'prepared')
        self.assertEqual(list(self.report.parent.glob('.*')), [])
        database.verify(self.root, digest, 24)

    def test_diagnostic_io_failure_never_masks_rejection_or_changes_verdict(self):
        with patch.object(database.os, 'replace', side_effect=OSError('fixture write failure')):
            self.status['built'] = (self.clock-dt.timedelta(hours=36)).isoformat()
            with self.assertRaises(database.DatabaseStatusError) as rejected:
                self.prepare_report()
            self.assertEqual(rejected.exception.details['reason'], 'stale')
            self.assertFalse((self.root/'receipt.json').exists())
            self.root = Path(self.temp.name)/'accepted'
            self.status['built'] = (self.clock-dt.timedelta(hours=1)).isoformat()
            digest = self.prepare_report()
        self.assertFalse(self.report.exists())
        self.assertIn('Unable to persist', database.sys.stderr.getvalue())
        self.assertIn('\"reason\": \"stale\"', database.sys.stderr.getvalue())
        self.assertIn('\"result\": \"prepared\"', database.sys.stderr.getvalue())
        self.assertEqual(list(self.report.parent.glob('.*')), [])
        database.verify(self.root, digest, 24)

    def test_diagnostics_cannot_mutate_snapshot(self):
        with self.assertRaisesRegex(ValueError, 'outside the snapshot'):
            database.prepare(self.root, 24, self.root/'receipt.json')
        self.assertFalse(self.root.exists())


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
