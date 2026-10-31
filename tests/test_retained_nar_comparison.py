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

    def test_bytecode_payload_hash_distinguishes_header_only_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            nar = Path(temp)/'nar'
            payload = b'public synthetic bytecode body'
            nar.write_bytes(b'ABCD' + m.struct.pack('<III', 0, 123, 7) + payload)
            db = sqlite3.connect(':memory:')
            db.execute('CREATE TABLE files(caseid,profile,path,kind,size,executable,hash,header)')
            m.inventory(db, 1, 'test', nar, {'type': 'directory', 'entries': {'fixture.pyc': {'type': 'regular', 'size': nar.stat().st_size, 'narOffset': 0}}})
            header = json.loads(db.execute("SELECT header FROM files WHERE path='fixture.pyc'").fetchone()[0])
            self.assertEqual(header['timestamp'], 123)
            self.assertEqual(header['payloadSha256'], hashlib.sha256(payload).hexdigest())

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

    def test_failure_diagnostics_are_fixed_and_do_not_leak(self):
        marker = 'PRIVATE_TOKEN_CONTENT_URL'
        examples = [(MemoryError(marker), 'memory-limit'),
                    (OSError(m.errno.ENOSPC, marker), 'disk-space'),
                    (OSError(m.errno.EFBIG, marker), 'file-size-limit'),
                    (m.subprocess.TimeoutExpired([marker], 1), 'tool-timeout'),
                    (m.zipfile.BadZipFile(marker), 'zip-format'),
                    (m.tarfile.ReadError(marker), 'tar-format'),
                    (m.json.JSONDecodeError(marker, marker, 0), 'json-format'),
                    (KeyError(marker), 'data-schema'),
                    (RuntimeError(marker), 'unexpected')]
        for error, category in examples:
            result = m.failure(error)
            self.assertEqual(result['category'], category)
            self.assertIn(result['stage'], m.STAGES)
            self.assertNotIn(marker, json.dumps(result))
            self.assertFalse(result['authorityClaim'])
        with self.assertRaises(m.Blocked):
            m.mark(marker)

    def test_retained_comparison_makes_no_public_cache_request(self):
        source = Path(m.__file__).read_text()
        self.assertNotIn('opener.open', source)
        self.assertNotIn('urllib.request', source)
        self.assertIn("'requestedDuringThisRun': False", source)
        self.assertIn("'publicCacheVerification': {'status': 'unavailable'", source)

    def test_content_facts_prove_only_known_index_block_order(self):
        prefix = b'//\n// This file has been generated by [index-modules](https://npmjs.com/index-modules)\n//\n\nconst properties = {}\n\n'
        suffix = b'export default Object.create(null, properties)\n'
        def block(name):
            return (f'import * as _{name} from "./{name}.mjs"\n'
                    f'if ("default" in _{name}) properties.{name} = {{ enumerable: true, get: () => _{name}.default }}\n'
                    f'export {{ _{name} as {name} }}\n\n').encode()
        path = m.ROOT_PREFIX+'packages/xo-server/src/api/index.mjs'
        a = m.content_facts(path, prefix+block('alpha')+block('beta')+suffix)
        b = m.content_facts(path, prefix+block('beta')+block('alpha')+suffix)
        self.assertTrue(a['grammarMatched'] and b['grammarMatched'])
        self.assertNotEqual(a['orderedModulesSha256'], b['orderedModulesSha256'])
        self.assertEqual(a['canonicalContentSha256'], b['canonicalContentSha256'])
        bad = m.content_facts(path, prefix+block('alpha')+b'unknown code\n'+suffix)
        self.assertFalse(bad['grammarMatched'])

    def test_content_facts_search_rows_and_precise_reference_normalization(self):
        path = m.ROOT_PREFIX+'docs/build-embed/search-doc.json'
        a = m.content_facts(path, json.dumps({'searchDocs': [{'url': '/a'}, {'url': '/b'}], 'options': {}}).encode())
        b = m.content_facts(path, json.dumps({'searchDocs': [{'url': '/b'}, {'url': '/a'}], 'options': {}}).encode())
        self.assertEqual(a['documentMultisetSha256'], b['documentMultisetSha256'])
        self.assertNotEqual(a['orderedDocumentsSha256'], b['orderedDocumentsSha256'])
        js = m.ROOT_PREFIX+'docs/build-embed/assets/js/main.123abc45.js'
        old = m.content_facts(js, b'"search-doc-1793403503498.json"')
        new = m.content_facts(js, b'"search-doc-1793411292876.json"')
        self.assertEqual(old['searchGuidNormalizedSha256'], new['searchGuidNormalizedSha256'])
        changed = m.content_facts(js, b'"search-doc-1793411292876.json"; extra')
        self.assertNotEqual(old['searchGuidNormalizedSha256'], changed['searchGuidNormalizedSha256'])
        html = m.ROOT_PREFIX+'docs/build-embed/index.html'
        old = m.content_facts(html, b'<script src="/assets/js/main.123abc45.js"></script>')
        new = m.content_facts(html, b'<script src="/assets/js/main.456abc78.js"></script>')
        self.assertEqual(old['searchGuidAndAssetReferencesNormalizedSha256'], new['searchGuidAndAssetReferencesNormalizedSha256'])
        with self.assertRaises(m.Blocked):
            m.content_facts(path, b'{"other":[]}')

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
