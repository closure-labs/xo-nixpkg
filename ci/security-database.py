#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare and verify one run-local Grype snapshot; caller anchors receipt hash."""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess


def now():
    return dt.datetime.now(dt.timezone.utc)


def stamp(value):
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('database timestamp must have timezone')
    return parsed


def files(root):
    result = {}
    if root.is_symlink() or not root.is_dir():
        raise ValueError('database root must be a real directory')
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError('database contains nonregular entry')
        with path.open('rb') as handle:
            result[str(path.relative_to(root))] = hashlib.file_digest(handle, 'sha256').hexdigest()
    if not result:
        raise ValueError('database has no bytes')
    return result


def environment(root):
    env = {k: v for k, v in os.environ.items() if not k.startswith('GRYPE_')}
    env.update(GRYPE_DB_CACHE_DIR=str(root / 'db'), GRYPE_DB_MAX_ALLOWED_BUILT_AGE='48h',
               GRYPE_DB_VALIDATE_AGE='true', GRYPE_DB_AUTO_UPDATE='false')
    return env


def grype(root, *args):
    return subprocess.check_output(['grype', '--config', str(root / 'grype.yaml'), *args],
                                   env=environment(root), text=True)


def validate_status(status, maximum_age=48):
    if status.get('valid') is not True or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', str(status.get('schemaVersion', ''))):
        raise ValueError('invalid database status/schema')
    age = now() - stamp(status['built'])
    if not dt.timedelta(0) <= age <= dt.timedelta(hours=maximum_age):
        raise ValueError('database is future-dated or stale')


def verify(root, expected, maximum_age=48):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('snapshot must be a real directory')
    receipt = root / 'receipt.json'
    if receipt.is_symlink() or not receipt.is_file():
        raise ValueError('missing regular database receipt')
    raw = receipt.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('database receipt does not match caller anchor')
    value = json.loads(raw)
    if value.get('schema') != 1 or value.get('onlineUpdate') is not True:
        raise ValueError('snapshot lacks online preparation')
    age = now() - stamp(value['preparedAt'])
    if not dt.timedelta(0) <= age <= dt.timedelta(hours=4):
        raise ValueError('snapshot is not from current qualification run')
    if {p.name for p in root.iterdir()} != {'db', 'receipt.json', 'grype.yaml'}:
        raise ValueError('unexpected snapshot entries')
    config = root / 'grype.yaml'
    if config.is_symlink() or config.read_bytes() != b'{}\n':
        raise ValueError('snapshot configuration changed')
    if files(root / 'db') != value['files']:
        raise ValueError('database snapshot mutated')
    if json.loads(grype(root, 'version', '-o', 'json')) != value['scanner']:
        raise ValueError('database scanner version changed')
    status = json.loads(grype(root, 'db', 'status', '-o', 'json'))
    validate_status(status, maximum_age)
    for key in ('built', 'schemaVersion'):
        if status[key] != value['database'][key]:
            raise ValueError('database identity changed')
    if files(root / 'db') != value['files']:
        raise ValueError('database verification mutated snapshot')
    return value


def prepare(root, maximum_age=48):
    if root.is_symlink():
        raise ValueError('snapshot directory cannot be a symlink')
    root.mkdir(parents=True, exist_ok=True)
    if list(root.iterdir()):
        raise ValueError('preparation requires empty fresh directory')
    (root / 'grype.yaml').write_bytes(b'{}\n')
    # Force the native updater to consult the approved online listing even when
    # the parent environment contains cache/configuration overrides.
    online_env = environment(root)
    online_env['GRYPE_DB_REQUIRE_UPDATE_CHECK'] = 'true'
    subprocess.run(['grype', '--config', str(root / 'grype.yaml'), 'db', 'update'],
                   env=online_env, check=True, stdout=subprocess.DEVNULL)
    status = json.loads(grype(root, 'db', 'status', '-o', 'json'))
    validate_status(status, maximum_age)
    value = {'schema': 1, 'onlineUpdate': True, 'preparedAt': now().isoformat(),
             'database': {k: status[k] for k in ('built', 'schemaVersion')},
             'scanner': json.loads(grype(root, 'version', '-o', 'json')),
             'files': files(root / 'db')}
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    (root / 'receipt.json').write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['prepare', 'verify'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('receipt_sha256', nargs='?')
    parser.add_argument('--max-age-hours',type=int,choices=[24,48],default=48)
    args = parser.parse_args()
    if args.operation == 'prepare':
        if args.receipt_sha256:
            parser.error('prepare does not accept an existing receipt')
        print(prepare(args.directory.resolve() if not args.directory.is_symlink() else args.directory, args.max_age_hours))
    else:
        if not args.receipt_sha256:
            parser.error('verify requires trusted caller receipt SHA256')
        verify(args.directory, args.receipt_sha256, args.max_age_hours)


if __name__ == '__main__':
    main()
