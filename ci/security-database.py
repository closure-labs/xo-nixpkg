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
import sys
import tempfile
import time


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


def status_diagnostics(status, maximum_age):
    # Only retain typed, normalized metadata, never status paths/errors or URLs.
    checked = now().astimezone(dt.timezone.utc)
    details = {'checkedAt': checked.isoformat(), 'builtAt': None, 'ageHours': None, 'maximumAgeHours': maximum_age,
               'schemaVersion': None, 'valid': None, 'reason': 'invalid_status'}
    if not isinstance(status, dict):
        return details
    if isinstance(status.get('valid'), bool):
        details['valid'] = status['valid']
    schema = status.get('schemaVersion')
    if isinstance(schema, str) and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', schema):
        details['schemaVersion'] = schema
    try:
        built = stamp(status['built'])
        age = checked - built
        details.update(builtAt=built.isoformat(), ageHours=round(age.total_seconds() / 3600, 6))
    except (KeyError, TypeError, AttributeError, ValueError, OverflowError):
        details['reason'] = 'invalid_timestamp'
        return details
    if details['valid'] is not True or details['schemaVersion'] is None:
        return details
    details['reason'] = ('future_dated' if age < dt.timedelta(0) else
                         'stale' if age > dt.timedelta(hours=maximum_age) else 'accepted')
    return details


class DatabaseStatusError(ValueError):
    def __init__(self, details):
        self.details = details
        super().__init__('database rejected: ' + json.dumps(details, sort_keys=True))


def validate_status(status, maximum_age=48):
    details = status_diagnostics(status, maximum_age)
    if details['reason'] != 'accepted':
        raise DatabaseStatusError(details)
    return details


def update_database(root, diagnostics):
    # Retry only recognized transport/server failures, never a stale successful
    # download. A second successful update must still pass normal validation.
    online_env = environment(root)
    online_env['GRYPE_DB_REQUIRE_UPDATE_CHECK'] = 'true'
    transient = re.compile(
        r'i/o timeout|TLS handshake timeout|connection reset by peer|'
        r'temporary failure in name resolution|unexpected EOF|'
        r'(?:status(?: code)?|response code|HTTP)[:= ]+(?:429|500|502|503|504)\b', re.I)
    for attempt in range(2):
        try:
            subprocess.run(['grype', '--config', str(root / 'grype.yaml'), 'db', 'update'],
                           env=online_env, check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, text=True)
            diagnostics['updates'].append({'exitCode': 0})
            return
        except subprocess.CalledProcessError as error:
            retryable = error.returncode > 0 and bool(transient.search(error.stderr or ''))
            diagnostics['updates'].append({'exitCode': error.returncode, 'transient': retryable})
            if attempt or not retryable:
                raise
            print('Transient database update failure; retrying once in 5 seconds.', file=sys.stderr)
            time.sleep(5)


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


def write_diagnostics(path, diagnostics):
    if path is None:
        return False
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='.' + path.name + '.', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(diagnostics, sort_keys=True) + '\n')
        # Atomic replacement replaces a destination symlink, never its target.
        os.replace(temporary, path)
        return True
    except OSError:
        print('Unable to persist database preparation diagnostics.', file=sys.stderr)
        print(json.dumps(diagnostics, sort_keys=True), file=sys.stderr)
        return False
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def prepare(root, maximum_age=48, diagnostics_path=None):
    if diagnostics_path is not None and diagnostics_path.resolve().is_relative_to(root.resolve()):
        raise ValueError('diagnostics must be outside the snapshot')
    diagnostics = {'schema': 1, 'result': 'preparing', 'stage': 'setup',
                   'maximumAgeHours': maximum_age, 'updates': [], 'database': None}
    try:
        if root.is_symlink():
            raise ValueError('snapshot directory cannot be a symlink')
        root.mkdir(parents=True, exist_ok=True)
        if list(root.iterdir()):
            raise ValueError('preparation requires empty fresh directory')
        (root / 'grype.yaml').write_bytes(b'{}\n')
        diagnostics['stage'] = 'update'
        write_diagnostics(diagnostics_path, diagnostics)
        update_database(root, diagnostics)
        diagnostics['stage'] = 'status'
        try:
            raw_status = grype(root, 'db', 'status', '-o', 'json')
        except subprocess.CalledProcessError as error:
            diagnostics['statusExitCode'] = error.returncode
            # Grype may emit usable status JSON even when it rejects the DB.
            try:
                diagnostics['database'] = status_diagnostics(json.loads(error.output), maximum_age)
            except (ValueError, TypeError):
                pass
            raise
        diagnostics['statusExitCode'] = 0
        status = json.loads(raw_status)
        try:
            diagnostics['database'] = validate_status(status, maximum_age)
        except DatabaseStatusError as error:
            diagnostics['database'] = error.details
            raise
        diagnostics['stage'] = 'receipt'
        value = {'schema': 1, 'onlineUpdate': True, 'preparedAt': now().isoformat(),
                 'database': {k: status[k] for k in ('built', 'schemaVersion')},
                 'scanner': json.loads(grype(root, 'version', '-o', 'json')),
                 'files': files(root / 'db')}
        raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        (root / 'receipt.json').write_bytes(raw)
        diagnostics.update(result='prepared', stage='complete')
        return hashlib.sha256(raw).hexdigest()
    except BaseException:
        diagnostics['result'] = 'failed'
        raise
    finally:
        # The report is not an authorization receipt and lives beyond cleanup of
        # the run-local snapshot. Never copy unfiltered subprocess output here.
        report = json.dumps(diagnostics, sort_keys=True) + '\n'
        persisted = write_diagnostics(diagnostics_path, diagnostics)
        if diagnostics['result'] != 'prepared' and (diagnostics_path is None or persisted):
            print(report, end='', file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['prepare', 'verify'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('receipt_sha256', nargs='?')
    parser.add_argument('--max-age-hours',type=int,choices=[24,48],default=48)
    parser.add_argument('--diagnostics-json', type=Path, help='preparation report outside the snapshot')
    args = parser.parse_args()
    if args.operation == 'prepare':
        if args.receipt_sha256:
            parser.error('prepare does not accept an existing receipt')
        print(prepare(args.directory.resolve() if not args.directory.is_symlink() else args.directory, args.max_age_hours, args.diagnostics_json))
    else:
        if args.diagnostics_json:
            parser.error('diagnostics are only available for prepare')
        if not args.receipt_sha256:
            parser.error('verify requires trusted caller receipt SHA256')
        verify(args.directory, args.receipt_sha256, args.max_age_hours)


if __name__ == '__main__':
    main()
