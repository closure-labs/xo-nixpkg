# SPDX-License-Identifier: Apache-2.0
"""Synthetic fixtures only; no network or package execution."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location('retained_nar_comparison', Path(__file__).resolve().parents[1]/'ci/compare-retained-nars.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class GuardTests(unittest.TestCase):
    def test_json_duplicate_and_nonfinite_fail(self):
        for raw in ['{"a":1,"a":2}', '{"a":NaN}']:
            with self.assertRaises(m.Blocked):
                m.decode(raw)
        self.assertEqual(m.decode('{"a":1}'), {'a': 1})

    def test_names_reject_escape_and_control(self):
        for name in ['../a', '/a', 'a/../b', 'a//b', './a', 'a\\b', 'a\n', '']:
            with self.assertRaises(m.Blocked):
                m.safe_name(name)
        self.assertEqual(m.safe_name('nar/example.nar.zst'), 'nar/example.nar.zst')

    def test_hash_encodings(self):
        self.assertEqual(m.sri('sha256:'+'0'*52), 'sha256-'+base64.b64encode(bytes(32)).decode())
        for value in ['sha256:bad', None, 'md5-x', 'sha256-'+'A'*44]:
            with self.assertRaises(m.Blocked):
                m.sri(value)

    def test_zip_links_and_oversized_members_fail(self):
        for mode in [stat.S_IFLNK, stat.S_IFIFO]:
            with io.BytesIO() as blob:
                with zipfile.ZipFile(blob, 'w') as archive:
                    info = zipfile.ZipInfo('bad'); info.external_attr = (mode|0o777)<<16
                    archive.writestr(info, b'x')
                blob.seek(0)
                with zipfile.ZipFile(blob) as archive, self.assertRaises(m.Blocked):
                    m.zip_members(archive)
        with io.BytesIO() as blob:
            with zipfile.ZipFile(blob, 'w') as archive:
                archive.writestr('x', b'1')
                archive.getinfo('x').file_size = 4*m.GIB
                with self.assertRaises(m.Blocked):
                    m.zip_members(archive)

    def test_zip_duplicate_fails(self):
        info = zipfile.ZipInfo('x')
        fake = type('Archive', (), {'infolist': lambda _: [info, info]})()
        with self.assertRaises(m.Blocked):
            m.zip_members(fake)

    def test_transport_hash_and_sequence(self):
        data = b'public synthetic archive'
        with io.BytesIO() as blob:
            with zipfile.ZipFile(blob, 'w') as archive:
                archive.writestr('distribution-cache.tar.part-000', data)
            blob.seek(0)
            with zipfile.ZipFile(blob) as archive:
                manifest = {'schema': 1, 'parts': {'distribution-cache.tar.part-000': {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}}, 'archiveSha256': hashlib.sha256(data).hexdigest(), 'archiveSize': len(data)}
                self.assertEqual(m.transport_parts(archive, manifest), ['distribution-cache.tar.part-000'])
                manifest['archiveSha256'] = '0'*64
                with self.assertRaises(m.Blocked):
                    m.transport_parts(archive, manifest)
                manifest['parts'] = {'distribution-cache.tar.part-001': {'size': len(data), 'sha256': '0'*64}}
                with self.assertRaises(m.Blocked):
                    m.transport_parts(archive, manifest)

    def test_tar_links_fail_without_following(self):
        with io.BytesIO() as tarblob:
            with tarfile.open(fileobj=tarblob, mode='w') as tar:
                entry = tarfile.TarInfo('link'); entry.type = tarfile.SYMTYPE; entry.linkname = '/etc/passwd'; tar.addfile(entry)
            with io.BytesIO() as blob:
                with zipfile.ZipFile(blob, 'w') as archive:
                    archive.writestr('part', tarblob.getvalue())
                blob.seek(0)
                with zipfile.ZipFile(blob) as archive, self.assertRaises(m.Blocked):
                    list(m.tar_members(archive, ['part']))

    def test_wrong_run_source_or_attempt_fail_before_download(self):
        case = m.CASES[0]
        good = {'id': case['run'], 'run_attempt': case['attempt'], 'head_sha': case['source'], 'head_branch': 'main', 'path': '.github/workflows/qualification.yml', 'repository': {'full_name': m.REPO}, 'head_repository': {'full_name': m.REPO}, 'status': 'completed', 'conclusion': 'success'}
        for key, value in [('id', 1), ('run_attempt', 2), ('head_sha', '0'*40), ('conclusion', 'failure')]:
            with patch.object(m, 'api', return_value=dict(good, **{key: value})), patch.object(m, 'run') as tool, tempfile.TemporaryDirectory() as temp:
                with self.assertRaisesRegex(m.Blocked, '^producer-binding$'):
                    m.prepare(case, Path(temp))
                tool.assert_not_called()

    def test_inventory_bounds_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            nar = Path(temp)/'nar'; nar.write_bytes(b'abc')
            db = sqlite3.connect(':memory:')
            db.execute('CREATE TABLE files(caseid,profile,path,kind,size,executable,hash,header)')
            node = {'type': 'directory', 'entries': {'file': {'type': 'regular', 'size': 3, 'narOffset': 0}, 'link': {'type': 'symlink', 'target': '/private/not-opened'}}}
            self.assertEqual(m.inventory(db, 1, 'test', nar, node), 3)
            self.assertEqual(db.execute("SELECT hash FROM files WHERE path='file'").fetchone()[0], hashlib.sha256(b'abc').hexdigest())
            for bad in [{'type': 'regular', 'size': 4, 'narOffset': 0}, {'type': 'regular', 'size': 1, 'narOffset': -1}, {'type': 'device'}]:
                with self.assertRaises(m.Blocked):
                    m.inventory(db, 2, 'test', nar, bad)

    def test_subprocess_failure_is_allowlisted_and_output_limited(self):
        with patch.object(m.subprocess, 'run', return_value=type('Result', (), {'returncode': 1})()):
            with self.assertRaisesRegex(m.Blocked, '^trusted-tool-failed$'):
                m.run(['uninvoked'])
        def write_output(*args, **kwargs):
            kwargs['stdout'].write(b'abc')
            self.assertIn('preexec_fn', kwargs)
            return type('Result', (), {'returncode': 0})()
        with patch.object(m.subprocess, 'run', side_effect=write_output):
            with self.assertRaisesRegex(m.Blocked, '^tool-output-bound$'):
                m.run(['uninvoked'], limit=2)

    def test_retained_identity_mismatch_stops_before_decompression(self):
        product = {'products': {p: {'storePath': m.ROOTS[p], 'narHash': 'sha256-'+base64.b64encode(bytes(32)).decode()} for p in m.PROFILES}}
        raw = b'StorePath: /nix/store/wrong\nNarHash: sha256:'+b'0'*52+b'\n'
        class Reader:
            def read(self):
                return raw
        class Tar:
            def extractfile(self, member):
                return Reader()
        member = type('Member', (), {'isfile': lambda _: True, 'size': len(raw)})()
        members = [(Path(m.ROOTS[p]).name[:32]+'.narinfo', member, Tar()) for p in m.PROFILES]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'a.zip'
            with zipfile.ZipFile(path, 'w'):
                pass
            with patch.object(m, 'transport_parts', return_value=[]), patch.object(m, 'tar_members', return_value=iter(members)), patch.object(m, 'run') as tool:
                with self.assertRaisesRegex(m.Blocked, '^retained-nar-identity$'):
                    m.compare_case(m.CASES[0], {'archive': path, 'product': product, 'transport': {}}, Path(temp), None, {})
                tool.assert_not_called()

    def test_timeout_is_not_converted_to_success(self):
        with patch.object(m.subprocess, 'run', side_effect=m.subprocess.TimeoutExpired(['uninvoked'], 1)):
            with self.assertRaises(m.subprocess.TimeoutExpired):
                m.run(['uninvoked'], timeout=1)

    def test_no_authority_or_publication(self):
        workflow = (Path(__file__).resolve().parents[1]/'.github/workflows/compare-retained-nars.yml').read_text()
        self.assertNotIn('write', workflow)
        self.assertNotIn('secrets.', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('timeout --signal=TERM --kill-after=15s 2700s', workflow)
        self.assertIn('attestations: read', workflow)
        self.assertNotIn('pull_request_target', workflow)


if __name__ == '__main__':
    unittest.main()
