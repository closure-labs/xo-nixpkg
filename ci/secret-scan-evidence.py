#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only, fail-closed scanner bootstrap evidence; never an authority proof."""
import argparse
import json
import math
import os
from pathlib import Path
import resource
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).with_name('decisions')))
import operations

MAX_JSON = 16 * 1024 * 1024
STAGES = ('engine-fixtures', 'complete-history', 'security-fixtures')


def history_failures(output):
    """Retain only fixed-category counters, never arbitrary child output."""
    if output.tell() > 16384:
        return []
    output.seek(0)
    try:
        lines = output.read().decode('utf-8').splitlines()
        if len(lines) > 32:
            return []
        records = []
        for line in lines:
            value = json.loads(line)
            if not isinstance(value, dict):
                return []
            if value.get('stage') != 'history-batch':
                # The final generic blocked record is deliberately not copied.
                continue
            if (set(value) != {'schema', 'stage', 'status', 'batch', 'commits', 'reason', 'seconds'}
                    or value['schema'] != 1 or value['status'] != 'blocked'
                    or type(value['batch']) is not int or not 0 <= value['batch'] < 100000
                    or type(value['commits']) is not int or not 1 <= value['commits'] <= 8
                    or not isinstance(value['reason'], str)
                    or value['reason'] not in {'timeout', 'scanner-start-failed', 'findings-or-scanner-error'}
                    or type(value['seconds']) not in (int, float)
                    or not math.isfinite(value['seconds']) or not 0 <= value['seconds'] <= 4000):
                return []
            records.append({'batch': value['batch'], 'commits': value['commits'],
                            'reason': value['reason'], 'seconds': value['seconds']})
        return records
    except (UnicodeError, ValueError):
        return []


def environment(home, inherited):
    """No tokens, user Git/Nix config, remote builders, or cache credentials."""
    home.mkdir()
    (home / 'nix').mkdir()
    (home / 'nix/nix.conf').write_text('')
    result = {key: inherited[key] for key in ('PATH', 'SSL_CERT_FILE', 'NIX_SSL_CERT_FILE', 'LANG', 'LC_ALL')
              if key in inherited}
    for key in ('XO_NIXPKG_SECRET_SCANNER', 'XO_NIXPKG_SECRET_SCANNER_IDENTITY'):
        result[key] = inherited[key]
    result.update(HOME=str(home), XDG_CONFIG_HOME=str(home / 'config'),
                  XDG_CACHE_HOME=str(home / 'cache'), NIX_CONF_DIR=str(home / 'nix'),
                  NIX_USER_CONF_FILES='/dev/null',
                  NIX_CONFIG='experimental-features = nix-command flakes\naccept-flake-config = false\n'
                             'sandbox = true\nbuilders =\naccess-tokens =\nrequire-sigs = true\n',
                  GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
                  PYTHONPATH=str(Path(operations.__file__).parent))
    return result


def write_json(path, value):
    content = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n'
    if len(content.encode()) > MAX_JSON:
        raise ValueError('Evidence exceeds bound')
    with path.open('x') as stream:
        stream.write(content)


def stage(name, command, limit, root, env, directory, json_output):
    started = time.monotonic()
    status = 'blocked'
    reason = 'scanner-or-fixture-error'
    def bounds():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_JSON, MAX_JSON))
    try:
        with tempfile.TemporaryFile() as output:
            result = operations.run(command, cwd=root, env=env, timeout=limit,
                                    stdout=output if json_output else subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, preexec_fn=bounds)
            if result.returncode != 0 and name in ('complete-history', 'introduced-history') and json_output:
                records = history_failures(output)
                if records:
                    write_json(directory / 'history-failures.json', {
                        'schema': 1, 'status': 'blocked', 'authorityClaim': False,
                        'reuseEligible': False, 'batches': records})
            if result.returncode == 0:
                if json_output:
                    if output.tell() >= MAX_JSON:
                        raise ValueError('Evidence exceeds bound')
                    output.seek(0)
                    value = json.loads(output.read())
                    if (not isinstance(value, dict) or value.get('status') != 'success'
                            or value.get('authorityClaim') is not False or value.get('reuseEligible') is not False):
                        raise ValueError('Incomplete evidence')
                    write_json(directory / (name + '.json'), value)
                status, reason = 'success', None
    except subprocess.TimeoutExpired:
        reason = 'timeout'
    except (OSError, ValueError, subprocess.SubprocessError):
        reason = 'invalid-or-unavailable-evidence'
    return {'stage': name, 'status': status, 'reason': reason,
            'seconds': round(time.monotonic() - started, 3)}


def clean_checkout(root, env):
    def bounds():
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    with tempfile.TemporaryFile() as output:
        result = operations.run(['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
                                 'status', '--porcelain', '--untracked-files=normal'],
                                cwd=root, env=env, timeout=30, stdout=output,
                                stderr=subprocess.DEVNULL, preexec_fn=bounds)
        if result.returncode or output.tell():
            raise ValueError('Scanner bootstrap requires a clean immutable checkout')


def run(root, directory, inherited, mode='full', base_sha=None, head_sha=None):
    if mode not in ('full', 'introduced'):
        raise ValueError('Invalid scan scope')
    scan_args = ['--mode', mode]
    history_stage = 'complete-history'
    if mode == 'introduced':
        if not all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}', value)
                   for value in (base_sha, head_sha)):
            raise ValueError('Exact scan inputs required')
        scan_args += ['--base-sha', base_sha, '--head-sha', head_sha]
        history_stage = 'introduced-history'
    elif base_sha or head_sha:
        raise ValueError('Full scan does not accept incremental identities')
    directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink() or any(directory.iterdir()):
        raise ValueError('Evidence directory must be empty and not a symlink')
    with tempfile.TemporaryDirectory(prefix='xo-scanner-native-') as temporary:
        env = environment(Path(temporary) / 'home', inherited)
        clean_checkout(root, env)
        commands = [
            (STAGES[0], [sys.executable, inherited['XO_NIXPKG_SCANNER_FIXTURE_SOURCE'],
                         '--scanner', env['XO_NIXPKG_SECRET_SCANNER'], '--config', str(root / '.gitleaks.toml')], 90, True),
            (history_stage, [sys.executable, inherited['XO_NIXPKG_HISTORY_SCAN_SOURCE'], *scan_args], 1260, True),
            (STAGES[2], ['nix', 'build', '--no-link', '--no-write-lock-file', '--no-accept-flake-config',
                         '--option', 'sandbox', 'true', '--option', 'builders', '',
                         'git+file://' + str(root) + '#lib.ciSecurityFixtures.x86_64-linux'], 600, False),
        ]
        # Independent stages: a history failure must not hide fixture diagnostics.
        with operations.budget(1980):
            results = [stage(name, command, limit, root, env, directory, capture)
                       for name, command, limit, capture in commands]
    success = all(item['status'] == 'success' for item in results)
    report = {'schema': 1, 'status': 'success' if success else 'blocked',
              'authorityClaim': False, 'reuseEligible': False, 'stages': results}
    write_json(directory / 'scanner-evidence.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mode', choices=('full', 'introduced'), default='full')
    parser.add_argument('--base-sha')
    parser.add_argument('--head-sha')
    args = parser.parse_args()
    try:
        report = run(Path.cwd().resolve(), args.output, os.environ, args.mode, args.base_sha, args.head_sha)
    except (KeyError, OSError, ValueError, subprocess.SubprocessError):
        report = {'schema': 1, 'status': 'blocked', 'authorityClaim': False, 'reuseEligible': False,
                  'reason': 'scanner-evidence-unavailable'}
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'success' else 1


if __name__ == '__main__':
    sys.exit(main())
