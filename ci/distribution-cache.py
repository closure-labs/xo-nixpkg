#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Transport authenticated exact Nix closures between jobs without a public cache."""
import argparse
import os
import sys
import time
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile

sys.path.insert(0, os.environ.get('MAESTRO_DECISION_CORE', str(Path(__file__).with_name('decisions'))))
import operations

PART_BYTES = 1_800_000_000
MAX_BYTES = 32 * 1024**3
MAX_MEMBERS = 100_000
PART = re.compile(r'distribution-cache\.tar\.part-[0-9]{3}')
NAR = re.compile(r'sha256-[A-Za-z0-9+/]{43}=')
STORE = re.compile(r'/nix/store/[a-z0-9]{32}-[^/\s]+')


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def identities(roots):
    require(isinstance(roots, list) and roots, 'Exact distribution roots are required')
    result = {}
    for root in roots:
        require(isinstance(root, dict) and set(root) == {'storePath', 'narHash'}
                and isinstance(root['storePath'], str) and STORE.fullmatch(root['storePath'])
                and isinstance(root['narHash'], str) and NAR.fullmatch(root['narHash']), 'Invalid distribution root identity')
        require(root['storePath'] not in result or result[root['storePath']] == root['narHash'], 'Conflicting distribution root identities')
        result[root['storePath']] = root['narHash']
    return result


def command(args):
    return operations.run(args, capture_output=True, check=True, timeout=1800).stdout


def verify_roots(roots):
    expected = identities(roots)
    records = json.loads(command(['nix', 'path-info', '--json', *sorted(expected)]))
    if isinstance(records, list):
        require(len({record['path'] for record in records}) == len(records), 'Duplicate imported root metadata')
        records = {record['path']: record for record in records}
    require(isinstance(records, dict) and set(records) == set(expected), 'Imported roots differ from exact requested identities')
    require(all(records[path].get('narHash') == nar_hash for path, nar_hash in expected.items()), 'Distribution NAR identity mismatch')


def safe_name(name):
    require(isinstance(name, str) and name and len(name) <= 512 and not name.startswith('/')
            and re.fullmatch(r'[A-Za-z0-9_./+-]+', name)
            and all(part not in ('', '.', '..') for part in name.split('/'))
            and str(PurePosixPath(name)) == name, 'Unsafe cache archive member')
    return name


def pack(cache, archive):
    count, total = 0, 0
    with tarfile.open(archive, 'w', format=tarfile.PAX_FORMAT) as output:
        for path in sorted(Path(cache).rglob('*')):
            require(not path.is_symlink() and (path.is_dir() or path.is_file()), 'Cache transport permits regular files and directories only')
            name = safe_name(path.relative_to(cache).as_posix())
            count += 1
            require(count <= MAX_MEMBERS, 'Cache has too many members')
            info = tarfile.TarInfo(name)
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ''
            if path.is_dir():
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                output.addfile(info)
            else:
                info.size, info.mode = path.stat().st_size, 0o644
                total += info.size
                require(total <= MAX_BYTES, 'Distribution closure exceeds 32 GiB transport budget')
                with path.open('rb') as handle:
                    output.addfile(info, handle)
    require(Path(archive).stat().st_size <= MAX_BYTES, 'Distribution archive exceeds 32 GiB transport budget')


def export(directory, roots):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    require(not any(path.name.startswith('distribution-cache.tar.part-') for path in directory.iterdir()), 'Refusing to overwrite an existing immutable distribution transport')
    expected = identities(roots)
    verify_roots(roots)
    with tempfile.TemporaryDirectory() as temporary:
        cache, archive = Path(temporary) / 'cache', Path(temporary) / 'distribution-cache.tar'
        # Explicit fast compression avoids XZ's expensive default for transient
        # multi-GiB CI transports. NAR identity is independent of compression.
        command(['nix', 'copy', '--to', cache.as_uri() + '?compression=zstd&compression-level=3', *sorted(expected)])
        require(cache.is_dir() and (cache / 'nix-cache-info').is_file(), 'Nix did not export a valid binary cache')
        pack(cache, archive)
        manifest = {'schema': 1, 'parts': {}, 'archiveSha256': digest(archive), 'archiveSize': archive.stat().st_size}
        with archive.open('rb') as source:
            index = 0
            while True:
                first = source.read(min(1024 * 1024, PART_BYTES))
                if not first:
                    break
                name = f'distribution-cache.tar.part-{index:03d}'
                require(index < 1000, 'Too many distribution transport parts')
                path = directory / name
                written = 0
                hasher = hashlib.sha256()
                with path.open('xb') as target:
                    block = first
                    while block:
                        target.write(block)
                        hasher.update(block)
                        written += len(block)
                        if written >= PART_BYTES:
                            break
                        block = source.read(min(1024 * 1024, PART_BYTES - written))
                manifest['parts'][name] = {'sha256': hasher.hexdigest(), 'size': written}
                index += 1
        return manifest


def validate_manifest(directory, manifest):
    require(isinstance(manifest, dict) and set(manifest) == {'schema', 'parts', 'archiveSha256', 'archiveSize'}
            and type(manifest['schema']) is int and manifest['schema'] == 1
            and isinstance(manifest['parts'], dict) and manifest['parts']
            and type(manifest['archiveSize']) is int and 0 < manifest['archiveSize'] <= MAX_BYTES
            and isinstance(manifest['archiveSha256'], str) and re.fullmatch(r'[a-f0-9]{64}', manifest['archiveSha256']), 'Invalid authenticated transport manifest')
    parts = sorted(manifest['parts'])
    require(parts == [f'distribution-cache.tar.part-{index:03d}' for index in range(len(parts))]
            and len(parts) <= 1000, 'Incomplete distribution transport part sequence')
    actual = {p.name for p in directory.iterdir() if p.name.startswith('distribution-cache.tar.part-')}
    require(actual == set(parts), 'Missing or unexpected distribution transport parts')
    total = 0
    for name in parts:
        record = manifest['parts'][name]
        path = directory / name
        require(PART.fullmatch(name) and isinstance(record, dict) and set(record) == {'sha256', 'size'}
                and type(record['size']) is int and 0 < record['size'] <= PART_BYTES
                and isinstance(record['sha256'], str) and re.fullmatch(r'[a-f0-9]{64}', record['sha256'])
                and not path.is_symlink() and path.is_file() and path.stat().st_size == record['size']
                and digest(path) == record['sha256'], 'Distribution transport part integrity mismatch')
        total += record['size']
    require(total == manifest['archiveSize'], 'Transport part sizes differ from archive size')
    return parts


def unpack(archive, cache):
    seen, total = set(), 0
    with tarfile.open(archive, 'r:') as source:
        for member in source:
            name = safe_name(member.name)
            require(name not in seen and len(seen) < MAX_MEMBERS and (member.isfile() or member.isdir())
                    and not member.linkname, 'Duplicate or nonregular cache archive member')
            seen.add(name)
            total += member.size
            require(0 <= member.size <= MAX_BYTES and total <= MAX_BYTES, 'Expanded cache exceeds transport budget')
            path = cache / name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as data, path.open('xb') as target:
                remaining = member.size
                while remaining:
                    block = data.read(min(1024 * 1024, remaining))
                    require(block, 'Truncated cache archive member')
                    target.write(block)
                    remaining -= len(block)
    require((cache / 'nix-cache-info').is_file(), 'Transport lacks binary cache metadata')


def restore(directory, manifest, roots, recursive_verify=True):
    """Caller MUST authenticate scans/product/manifest before calling this function."""
    directory = Path(directory)
    expected = identities(roots)
    parts = validate_manifest(directory, manifest)
    with tempfile.TemporaryDirectory() as temporary:
        archive, cache = Path(temporary) / 'distribution-cache.tar', Path(temporary) / 'cache'
        cache.mkdir()
        hasher = hashlib.sha256()
        with archive.open('xb') as target:
            for name in parts:
                with (directory / name).open('rb') as source:
                    for block in iter(lambda: source.read(1024 * 1024), b''):
                        target.write(block)
                        hasher.update(block)
        require(archive.stat().st_size == manifest['archiveSize'] and hasher.hexdigest() == manifest['archiveSha256'], 'Reassembled distribution archive integrity mismatch')
        unpack(archive, cache)
        with operations.budget(600):
            command(['nix', 'copy', '--from', cache.as_uri(), '--no-check-sigs', *sorted(expected)])
            verify_roots(roots)
            if recursive_verify:
                command(['nix', 'store', 'verify', '--no-trust', '--recursive', *sorted(expected)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--export', dest='exporting', action='store_true')
    action.add_argument('--restore', dest='restoring', action='store_true')
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--roots', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    roots = json.loads(args.roots.read_text())
    if args.exporting:
        args.manifest.write_text(json.dumps(export(args.directory, roots), sort_keys=True, indent=2) + '\n')
    else:
        restore(args.directory, json.loads(args.manifest.read_text()), roots)


if __name__ == '__main__':
    main()
