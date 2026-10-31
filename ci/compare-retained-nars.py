#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Hosted-only retained NAR comparison. Never imports or executes package output."""
import base64
import gc
import errno
import time
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import urllib.request
import urllib.error

REPO = 'closure-labs/xo-nixpkg'
CASES = [
    {'run': 41145005348, 'attempt': 1, 'source': '8273ea5be6d297fa5d5543630eb7311a3c932d66',
     'artifact': 13022125152, 'bytes': 2653386389,
     'digest': 'a60ea26548b7d97ebe9ed4ff28314aec1480eb7dcf7db664743d17b984964320'},
    {'run': 41158639922, 'attempt': 1, 'source': 'e8d8bfbfa4bacc322385f6f4454f619683c9691d',
     'artifact': 13026675909, 'bytes': 2653345566,
     'digest': '12d5218c48acf9fe54bf1914848fe5f519daf303ed2df44d8ccd2490d17ffa55'},
]
PROFILES = ('xo-latest', 'xo-stable', 'xo-rolling')
GIB = 1024**3
MAX_NAR = 3 * GIB
ALPHABET = '0123456789abcdfghijklmnpqrsvwxyz'
KEY_NAME = 'xen-orchestra-ce.cachix.org-1'
KEY = 'WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E='
ROOTS = {
    'xo-latest': '/nix/store/7vqm49jj6y11r8axlhr6rf3ms7hqlvn4-xen-orchestra-ce-6.10.0',
    'xo-stable': '/nix/store/kqf8wj1xwjkqvjwpaipcx393hil2c2fv-xen-orchestra-ce-6.9.1',
    'xo-rolling': '/nix/store/zh2pvbiwadzsxz5i3h7wp5x1wl44y5w0-xen-orchestra-ce-unstable-2026-10-29',
}


STAGE = 'initialization'
STARTED = time.monotonic()
FAILURE_RESERVE = bytearray(64 * 1024)
STAGES = frozenset(('initialization', 'resource-guards', 'producer-metadata', 'artifact-metadata',
                    'artifact-download', 'artifact-digest', 'archive-metadata', 'metadata-attestation',
                    'metadata-json', 'product-json', 'scans-json', 'public-cache-signatures', 'offline-setup', 'transport-digests',
                    'narinfo-inventory', 'compressed-nar-read', 'compressed-nar-digest', 'nar-decompress',
                    'nar-content-digest', 'nar-listing', 'nar-listing-json', 'file-inventory',
                    'source-recipes', 'summary'))


def mark(stage, case=None, profile=None):
    global STAGE
    require(stage in STAGES and (case is None or case in [c['run'] for c in CASES])
            and (profile is None or profile in PROFILES), 'diagnostic-stage-schema')
    STAGE = stage
    print(json.dumps({'status': 'progress', 'stage': stage, 'case': case, 'profile': profile,
                      'elapsedSeconds': round(time.monotonic()-STARTED, 3)}), flush=True)


def failure(error):
    # Never emit error text, filenames, URLs, subprocess arguments or payloads.
    category = 'unexpected'
    if isinstance(error, MemoryError):
        category = 'memory-limit'
    elif isinstance(error, subprocess.TimeoutExpired):
        category = 'tool-timeout'
    elif isinstance(error, json.JSONDecodeError):
        category = 'json-format'
    elif isinstance(error, zipfile.BadZipFile):
        category = 'zip-format'
    elif isinstance(error, tarfile.TarError):
        category = 'tar-format'
    elif isinstance(error, urllib.error.HTTPError):
        category = 'http-response'
    elif isinstance(error, urllib.error.URLError):
        category = 'network'
    elif isinstance(error, OSError):
        category = {errno.ENOMEM: 'memory-limit', errno.ENOSPC: 'disk-space',
                    errno.EFBIG: 'file-size-limit'}.get(error.errno, 'io-error')
    elif isinstance(error, (KeyError, TypeError, AttributeError, ValueError)):
        category = 'data-schema'
    frames = []
    trace = error.__traceback__
    allowed = {'main', 'prepare', 'run', 'api', 'decode', 'zip_members', 'transport_parts',
               'tar_members', 'narinfo', 'sri', 'verify_public_metadata', 'compare_case',
               'inventory', 'visit', 'differences'}
    while trace is not None:
        name = trace.tb_frame.f_code.co_name
        if trace.tb_frame.f_code.co_filename == __file__ and name in allowed:
            frames.append({'function': name, 'line': trace.tb_lineno})
        trace = trace.tb_next
    return {'status': 'blocked', 'code': str(error) if type(error) is Blocked else 'diagnostic-failed',
            'category': 'guard' if type(error) is Blocked else category, 'stage': STAGE,
            'frames': frames[-5:], 'authorityClaim': False}


class Blocked(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Blocked(code)


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Blocked('nonfinite-json')))


def safe_name(name):
    require(isinstance(name, str) and 0 < len(name) <= 4096 and '\\' not in name
            and all(ord(c) >= 32 and ord(c) != 127 for c in name), 'unsafe-archive-name')
    parts = PurePosixPath(name).parts
    require(not name.startswith('/') and parts and all(p not in ('.', '..') for p in parts)
            and str(PurePosixPath(name)) == name.rstrip('/'), 'unsafe-archive-name')
    return name.rstrip('/')


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def sri(value):
    require(isinstance(value, str), 'hash-schema')
    if re.fullmatch(r'sha256-[A-Za-z0-9+/]{43}=', value):
        require(len(base64.b64decode(value[7:], validate=True)) == 32, 'hash-schema')
        return value
    require(re.fullmatch('sha256:[' + ALPHABET + ']{52}', value), 'hash-schema')
    number = sum(ALPHABET.index(c) << (5*i) for i, c in enumerate(reversed(value[7:])))
    require(number < 1 << 256, 'hash-schema')
    return 'sha256-' + base64.b64encode(number.to_bytes(32, 'little')).decode()


def run(args, *, timeout=120, output=None, env=None, limit=2 * 1024**2):
    # All executables are trusted host tools; no fetched executable is invoked.
    def child_limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    with tempfile.TemporaryFile() as capture:
        target = output if output is not None else capture
        process = subprocess.run(args, stdout=target, stderr=subprocess.DEVNULL,
                                 timeout=timeout, env=env, check=False, preexec_fn=child_limits)
        require(process.returncode == 0, 'trusted-tool-failed')
        if output is not None:
            return None
        require(capture.tell() <= limit, 'tool-output-bound')
        capture.seek(0)
        return capture.read()


def api(endpoint):
    return decode(run(['gh', 'api', endpoint], timeout=45))


def zip_members(archive):
    members = {}
    total = 0
    require(len(archive.infolist()) <= 1024, 'zip-member-bound')
    for info in archive.infolist():
        name = safe_name(info.filename)
        require(name not in members and not info.flag_bits & 1, 'zip-duplicate-or-encrypted')
        mode = stat.S_IFMT(info.external_attr >> 16)
        require(mode in (0, stat.S_IFREG, stat.S_IFDIR) and not stat.S_ISLNK(info.external_attr >> 16), 'zip-member-type')
        total += info.file_size
        require(total <= 8 * GIB and info.file_size <= 3 * GIB, 'zip-size-bound')
        if not info.is_dir():
            members[name] = info
    return members


def prepare(case, work):
    mark('producer-metadata', case['run'])
    run_meta = api(f'repos/{REPO}/actions/runs/{case["run"]}')
    require(run_meta.get('id') == case['run'] and run_meta.get('run_attempt') == case['attempt']
            and run_meta.get('head_sha') == case['source'] and run_meta.get('head_branch') == 'main'
            and run_meta.get('path') == '.github/workflows/qualification.yml'
            and run_meta.get('repository', {}).get('full_name') == REPO
            and run_meta.get('head_repository', {}).get('full_name') == REPO
            and run_meta.get('status') == 'completed' and run_meta.get('conclusion') == 'success', 'producer-binding')
    mark('artifact-metadata', case['run'])
    artifact = api(f'repos/{REPO}/actions/artifacts/{case["artifact"]}')
    require(artifact.get('id') == case['artifact'] and artifact.get('name') == f'qualified-products-{case["run"]}-{case["attempt"]}'
            and artifact.get('workflow_run', {}).get('id') == case['run']
            and artifact.get('workflow_run', {}).get('head_sha') == case['source']
            and artifact.get('size_in_bytes') == case['bytes']
            and artifact.get('digest') == 'sha256:' + case['digest']
            and artifact.get('expired') is False, 'artifact-binding')
    destination = work / str(case['run'])
    destination.mkdir(mode=0o700)
    archive_path = destination / 'artifact.zip'
    mark('artifact-download', case['run'])
    with archive_path.open('xb') as output:
        run(['gh', 'api', f'repos/{REPO}/actions/artifacts/{case["artifact"]}/zip'], timeout=600, output=output, limit=case['bytes'])
    mark('artifact-digest', case['run'])
    require(archive_path.stat().st_size == case['bytes'] and digest(archive_path) == case['digest'], 'artifact-digest')
    values = {}
    mark('archive-metadata', case['run'])
    with zipfile.ZipFile(archive_path) as archive:
        members = zip_members(archive)
        for name, limit in [('product.json', 16 * 1024**2), ('scans.json', 128 * 1024**2)]:
            require(name in members and members[name].file_size <= limit, 'metadata-size')
            path = destination / name
            with archive.open(members[name]) as source, path.open('xb') as output:
                shutil.copyfileobj(source, output, 1024**2)
            # Signed exact file digest + immutable workflow/source/ref, not an artifact-name claim.
            mark('metadata-attestation', case['run'])
            run(['gh', 'attestation', 'verify', str(path), '--repo', REPO,
                 '--signer-workflow', REPO + '/.github/workflows/qualification.yml',
                 '--source-digest', case['source'], '--source-ref', 'refs/heads/main',
                 '--deny-self-hosted-runners', '--format', 'json'], timeout=180)
            mark('product-json' if name == 'product.json' else 'scans-json', case['run'])
            values[name] = decode(path.read_bytes())
    product, scans = values['product.json'], values['scans.json']
    producer = scans.get('producer', {})
    require(product.get('repository') == REPO and scans.get('repository') == REPO
            and product.get('revision') == scans.get('revision') == case['source']
            and producer.get('runId') == case['run'] and producer.get('runAttempt') == case['attempt']
            and producer.get('revision', case['source']) == case['source']
            and producer.get('workflow') == '.github/workflows/qualification.yml', 'attested-producer-binding')
    result = {'archive': archive_path, 'product': product, 'transport': scans['transport']}
    del values, scans
    gc.collect()
    require(set(product.get('products', {})) >= set(PROFILES), 'product-profile-schema')
    for profile in PROFILES:
        require(product['products'][profile]['storePath'] == ROOTS[profile], 'fixed-product-binding')
    return result


class Parts(io.RawIOBase):
    def __init__(self, archive, names):
        self.archive, self.names, self.current = archive, iter(names), None
    def readable(self):
        return True
    def readinto(self, buffer):
        while True:
            if self.current is None:
                name = next(self.names, None)
                if name is None:
                    return 0
                self.current = self.archive.open(name)
            data = self.current.read(len(buffer))
            if data:
                buffer[:len(data)] = data
                return len(data)
            self.current.close()
            self.current = None
    def close(self):
        if self.current:
            self.current.close()
        super().close()


def transport_parts(archive, transport):
    require(isinstance(transport, dict) and set(transport) == {'schema', 'parts', 'archiveSha256', 'archiveSize'}
            and transport['schema'] == 1 and isinstance(transport['parts'], dict), 'transport-schema')
    names = sorted(transport['parts'])
    require(names and names == [f'distribution-cache.tar.part-{i:03d}' for i in range(len(names))]
            and len(names) <= 8, 'transport-sequence')
    members = zip_members(archive)
    require({n for n in members if n.startswith('distribution-cache.tar.part-')} == set(names), 'transport-inventory')
    combined, total = hashlib.sha256(), 0
    for name in names:
        record = transport['parts'][name]
        require(set(record) == {'size', 'sha256'} and type(record['size']) is int
                and 0 < record['size'] <= 1_800_000_000
                and members[name].file_size == record['size'], 'transport-member-size')
        hasher = hashlib.sha256()
        with archive.open(name) as source:
            while block := source.read(1024**2):
                hasher.update(block); combined.update(block); total += len(block)
        require(hasher.hexdigest() == record['sha256'], 'transport-part-digest')
    require(type(transport['archiveSize']) is int and total == transport['archiveSize'] <= 6 * GIB
            and combined.hexdigest() == transport['archiveSha256'], 'transport-archive-digest')
    return names


def tar_members(archive, names):
    seen, total = set(), 0
    with io.BufferedReader(Parts(archive, names), 1024**2) as source, tarfile.open(fileobj=source, mode='r|') as tar:
        for member in tar:
            name = safe_name(member.name)
            require(name not in seen and len(seen) < 100000 and (member.isdir() or member.isfile()), 'tar-member-schema')
            seen.add(name); total += member.size
            require(0 <= member.size <= 3 * GIB and total <= 6 * GIB, 'tar-size-bound')
            yield name, member, tar


def narinfo(raw):
    fields = {}
    require(len(raw) <= 2 * 1024**2, 'narinfo-size')
    for line in raw.decode('utf8').splitlines():
        key, separator, value = line.partition(': ')
        require(separator and (key not in fields or key == 'Sig'), 'narinfo-schema')
        if key == 'Sig':
            fields.setdefault(key, []).append(value)
        else:
            fields[key] = value
    return fields



def verify_public_metadata(product, work):
    # Only fixed public narinfo metadata; never fetch or execute the public NAR.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise Blocked('public-metadata-redirect')
    opener = urllib.request.build_opener(NoRedirect())
    results = {}
    key = work/'cache-key.der'
    key.write_bytes(bytes.fromhex('302a300506032b6570032100') + base64.b64decode(KEY, validate=True))
    for profile in PROFILES:
        path = ROOTS[profile]
        url = 'https://xen-orchestra-ce.cachix.org/' + Path(path).name[:32] + '.narinfo'
        with opener.open(url, timeout=30) as response:
            require(response.status == 200 and response.geturl() == url, 'public-metadata-response')
            raw = response.read(65537)
        require(len(raw) <= 65536, 'public-metadata-bound')
        info = narinfo(raw)
        require(info.get('StorePath') == path and sri(info.get('NarHash')) == sri(product['products'][profile]['narHash'])
                and info.get('NarSize', '').isdigit() and 0 < int(info['NarSize']) <= MAX_NAR, 'public-metadata-identity')
        references = info.get('References', '').split()
        require(len(references) <= 10000 and references == sorted(set(references))
                and all(re.fullmatch(r'[a-z0-9]{32}-[^/\\\s]+', r) for r in references), 'public-reference-schema')
        signatures = [s[len(KEY_NAME)+1:] for s in info.get('Sig', []) if s.startswith(KEY_NAME+':')]
        require(len(signatures) == 1, 'public-signature-inventory')
        signature = base64.b64decode(signatures[0], validate=True)
        require(len(signature) == 64, 'public-signature-schema')
        message = ('1;' + path + ';' + info['NarHash'] + ';' + info['NarSize'] + ';'
                   + ','.join('/nix/store/'+r for r in references)).encode()
        (work/'signature').write_bytes(signature); (work/'fingerprint').write_bytes(message)
        run(['openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-rawin',
             '-inkey', str(key), '-sigfile', str(work/'signature'), '-in', str(work/'fingerprint')],
            env={'PATH': os.environ['PATH']})
        results[profile] = {'signatureVerified': True, 'matchesEarlierQualification': True,
                            'narHash': sri(info['NarHash']), 'narSize': int(info['NarSize'])}
    return results


def inventory(db, case, profile, nar, listing):
    size = nar.stat().st_size
    count = 0
    with nar.open('rb') as source:
        def visit(node, path='', depth=0):
            nonlocal count
            count += 1
            require(count <= 1_000_000 and depth <= 256 and isinstance(node, dict), 'nar-tree-bound')
            kind = node.get('type'); length = 0; executable = False; header = None
            if kind == 'directory':
                require(isinstance(node.get('entries'), dict), 'nar-directory-schema')
                hashed = ''
                for name, child in node['entries'].items():
                    require(isinstance(name, str) and name not in ('', '.', '..') and '/' not in name
                            and len(name) <= 255, 'nar-entry-name')
                    childpath = safe_name(path + '/' + name if path else name)
                    visit(child, childpath, depth + 1)
            elif kind == 'regular':
                length, offset = node.get('size'), node.get('narOffset')
                executable = node.get('executable', False)
                require(type(length) is int and type(offset) is int and type(executable) is bool
                        and 0 <= length <= MAX_NAR and 0 <= offset <= size and offset + length <= size, 'nar-file-range')
                source.seek(offset); hasher = hashlib.sha256(); remaining = length
                while remaining:
                    block = source.read(min(1024**2, remaining))
                    require(block, 'nar-file-truncated'); hasher.update(block); remaining -= len(block)
                hashed = hasher.hexdigest()
                if path.endswith('.pyc') and length >= 16:
                    source.seek(offset); raw = source.read(16)
                    flags, word1, word2 = struct.unpack('<III', raw[4:])
                    header = {'magic': raw[:4].hex(), 'flags': flags}
                    if flags == 0:
                        header.update(timestamp=word1, sourceSize=word2)
            elif kind == 'symlink':
                target = node.get('target')
                require(isinstance(target, str) and len(target) <= 4096, 'nar-symlink-schema')
                hashed = hashlib.sha256(target.encode()).hexdigest(); length = len(target.encode())
            else:
                raise Blocked('nar-node-type')
            db.execute('INSERT INTO files VALUES (?,?,?,?,?,?,?,?)',
                       (case, profile, path, kind, length, int(executable), hashed, json.dumps(header)))
        visit(listing)
    db.commit()
    return count


def compare_case(case, prepared, work, db, env):
    results = {}
    with zipfile.ZipFile(prepared['archive']) as archive:
        mark('transport-digests', case['run'])
        names = transport_parts(archive, prepared['transport'])
        mark('narinfo-inventory', case['run'])
        infos = {}
        targets = {Path(prepared['product']['products'][p]['storePath']).name[:32] + '.narinfo': p for p in PROFILES}
        for name, member, tar in tar_members(archive, names):
            if name in targets:
                require(member.isfile() and member.size <= 2 * 1024**2, 'root-narinfo-size')
                infos[targets[name]] = narinfo(tar.extractfile(member).read())
        require(set(infos) == set(PROFILES), 'root-narinfo-inventory')
        for profile in PROFILES:
            info, expected = infos[profile], prepared['product']['products'][profile]
            require(info.get('StorePath') == expected['storePath'] and sri(info.get('NarHash')) == sri(expected['narHash']), 'retained-nar-identity')
            url = safe_name(info.get('URL')); require(url.startswith('nar/') and info.get('Compression') == 'zstd', 'nar-transport-format')
            require(info.get('NarSize', '').isdigit() and 0 < int(info['NarSize']) <= MAX_NAR, 'nar-size-bound')
            with tempfile.TemporaryDirectory(dir=work, prefix='nar-data-') as temporary:
                temporary = Path(temporary); compressed, nar = temporary/'data.zst', temporary/'data.nar'
                mark('compressed-nar-read', case['run'], profile)
                found = False
                for name, member, tar in tar_members(archive, names):
                    if name == url:
                        require(member.isfile(), 'nar-transport-type')
                        with compressed.open('xb') as output:
                            shutil.copyfileobj(tar.extractfile(member), output, 1024**2)
                        found = True
                require(found and info.get('FileSize', '').isdigit()
                        and compressed.stat().st_size == int(info['FileSize']), 'nar-file-size')
                mark('compressed-nar-digest', case['run'], profile)
                require(sri(info.get('FileHash')) == 'sha256-' + base64.b64encode(bytes.fromhex(digest(compressed))).decode(), 'nar-compressed-digest')
                mark('nar-decompress', case['run'], profile)
                with nar.open('xb') as output:
                    run(['zstd', '--decompress', '--stdout', str(compressed)], timeout=180, output=output, env=env, limit=int(info['NarSize']))
                mark('nar-content-digest', case['run'], profile)
                require(nar.stat().st_size == int(info['NarSize'])
                        and 'sha256-' + base64.b64encode(bytes.fromhex(digest(nar))).decode() == sri(expected['narHash']), 'nar-content-digest')
                mark('nar-listing', case['run'], profile)
                listing = temporary/'listing.json'
                with listing.open('xb') as output:
                    run(['nix', '--offline', 'nar', 'ls', '--json', '--recursive', str(nar), '/'], timeout=180, output=output, env=env, limit=256 * 1024**2)
                require(listing.stat().st_size <= 256 * 1024**2, 'nar-listing-bound')
                mark('nar-listing-json', case['run'], profile)
                tree = decode(listing.read_bytes())
                mark('file-inventory', case['run'], profile)
                count = inventory(db, case['run'], profile, nar, tree)
                del tree; gc.collect()
                deriver = info.get('Deriver', 'unknown-deriver')
                require(re.fullmatch(r'(?:[a-z0-9]{32}-[^/\s]+\.drv|unknown-deriver)', deriver), 'deriver-schema')
                results[profile] = {'storePath': expected['storePath'], 'narHash': sri(expected['narHash']),
                                    'narSize': int(info['NarSize']), 'deriver': deriver, 'entries': count}
    return results


def differences(db):
    result = {}
    for profile in PROFILES:
        rows = db.execute('''SELECT a.path,a.kind,a.size,a.executable,a.hash,a.header,
                                   b.kind,b.size,b.executable,b.hash,b.header
            FROM files a LEFT JOIN files b ON b.caseid=? AND b.profile=a.profile AND b.path=a.path
            WHERE a.caseid=? AND a.profile=? AND (b.path IS NULL OR a.kind!=b.kind OR a.size!=b.size
                OR a.executable!=b.executable OR a.hash!=b.hash)
            UNION ALL SELECT b.path,NULL,NULL,NULL,NULL,NULL,b.kind,b.size,b.executable,b.hash,b.header
            FROM files b LEFT JOIN files a ON a.caseid=? AND a.profile=b.profile AND a.path=b.path
            WHERE b.caseid=? AND b.profile=? AND a.path IS NULL ORDER BY 1''',
            (CASES[1]['run'], CASES[0]['run'], profile, CASES[0]['run'], CASES[1]['run'], profile))
        count, samples = 0, []
        for row in rows:
            count += 1
            if len(samples) < 2000:
                samples.append({'relativePath': row[0], 'old': list(row[1:6]), 'new': list(row[6:])})
        result[profile] = {'differentEntries': count, 'sampleLimit': 2000, 'samples': samples}
    return result


def main():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == REPO, 'hosted-context-required')
    mark('resource-guards')
    resource.setrlimit(resource.RLIMIT_AS, (3 * GIB, 3 * GIB))
    resource.setrlimit(resource.RLIMIT_FSIZE, (6 * GIB, 6 * GIB))
    resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
    work, output = Path(sys.argv[1]), Path(sys.argv[2])
    work.mkdir(mode=0o700); output.mkdir(mode=0o755)
    require(shutil.disk_usage(work).free >= 12 * GIB, 'insufficient-hosted-disk')
    prepared = [prepare(case, work) for case in CASES]
    mark('public-cache-signatures')
    cache_signatures = verify_public_metadata(prepared[0]['product'], work)
    # No credential is passed to NAR parsing, decompression or metadata tools.
    os.environ.pop('GH_TOKEN', None); os.environ.pop('GITHUB_TOKEN', None)
    mark('offline-setup')
    home = work/'offline-home'; home.mkdir(mode=0o700)
    env = {'PATH': os.environ['PATH'], 'HOME': str(home), 'NIX_USER_CONF_FILES': '/dev/null',
           'NIX_CONFIG': 'experimental-features = nix-command\naccept-flake-config = false\naccess-tokens =\nsubstituters =\nbuilders =\n'}
    db = sqlite3.connect(work/'manifest.sqlite')
    db.execute('CREATE TABLE files(caseid INTEGER,profile TEXT,path TEXT,kind TEXT,size INTEGER,executable INTEGER,hash TEXT,header TEXT,PRIMARY KEY(caseid,profile,path)) WITHOUT ROWID')
    identities = []
    for case, data in zip(CASES, prepared):
        identities.append(compare_case(case, data, work, db, env))
        data['archive'].unlink()
    mark('source-recipes')
    sources = {}
    for path in ['default.nix', 'flake.nix', 'flake.lock', 'devenv.lock', 'nix/sources/xen-orchestra.json', 'nix/runtime-node.nix', 'nix/yarn-platform-tools.nix']:
        sources[path] = [hashlib.sha256(run(['git', 'show', case['source']+':'+path], env=env)).hexdigest() for case in CASES]
    mark('summary')
    result = {'schema': 1, 'status': 'compared', 'authorityClaim': False, 'cases': CASES,
              'publicCacheSignatures': cache_signatures, 'identities': identities, 'recipeFileHashes': sources, 'differences': differences(db),
              'packageCodeExecuted': False, 'storeImported': False, 'cacheMutated': False,
              'nixVersion': run(['nix','--version'], env=env).decode().strip()}
    raw = json.dumps(result, sort_keys=True, indent=2).encode()
    require(len(raw) <= 5 * 1024**2, 'diagnostic-output-bound')
    (output/'summary.json').write_bytes(raw+b'\n')
    print(json.dumps({'status': 'compared', 'differentEntries': {p:v['differentEntries'] for p,v in result['differences'].items()}, 'authorityClaim': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        FAILURE_RESERVE = None
        print(json.dumps(failure(error)), flush=True)
        raise SystemExit(1)
