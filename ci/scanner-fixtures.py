#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded, synthetic exact-engine regression fixtures; never relax scanner policy.

Pass the packaged engine explicitly. --reference optionally checks another build
of that engine. Executable hashes identify builds, not their Go regexp backend;
Nix must pin and expose the backend/build recipe separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile
import time
sys.path.insert(0, str(Path(__file__).with_name("decisions")))
import operations

REPORT_LIMIT = 4 * 1024 * 1024
TIMEOUT = 60
KEY_COUNT = 32
PADDING_BYTES = 256 * 1024
MATCH = re.compile(r'(?:api_key|key)"\s*:\s*"[a-f0-9]{64}"')


class FixtureError(RuntimeError):
    pass


def fixture_files():
    keys = [hashlib.sha256(('public-fixture-identity-%d' % i).encode()).hexdigest() for i in range(KEY_COUNT)]
    credential = hashlib.sha256(b'synthetic-not-a-real-credential').hexdigest()
    compact = json.dumps({'rows': [{'key': key} for key in keys], 'api_key': credential,
                          'padding': 'z' * PADDING_BYTES}, separators=(',', ':')) + '\n'
    # Exact existing policy permits only this indentation and complete key line.
    pretty = '{\n  "rows": [\n' + ',\n'.join(
        '        {\n          "key": "' + key + '",\n          "kind": "fixture"\n        }' for key in keys
    ) + '\n  ],\n  "api_key": "' + credential + '"\n}\n'
    prefix = 'automation/decisions/security/'
    return {prefix + 'a' * 64 + '.json': compact,
            prefix + 'b' * 64 + '.json': pretty,
            'external.json': '{"key":"' + keys[0] + '"}\n'}


def expected_findings(files):
    expected = []
    for path, content in files.items():
        for line_number, line in enumerate(content.splitlines(), 1):
            for match in MATCH.finditer(line):
                if path.startswith('automation/decisions/security/') and re.fullmatch(r'          "key": "[a-f0-9]{64}",', line):
                    continue
                # Gitleaks 8.30.1 retains a preceding newline when calculating
                # columns after line one. Pin its current report semantics too.
                expected.append(('generic-api-key', path, line_number, line_number,
                                 match.start() + 1 + (line_number > 1), match.end() + (line_number > 1)))
    return sorted(expected)


def _limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (REPORT_LIMIT, REPORT_LIMIT))


def run_quiet(argv, cwd, timeout=TIMEOUT):
    # Do not inherit policy overrides or repository selectors from the caller.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('GITLEAKS_', 'GIT_'))}
    env.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull})
    try:
        return operations.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout, check=False, preexec_fn=_limits).returncode
    except (OSError, subprocess.TimeoutExpired):
        raise FixtureError('fixture subprocess failed or timed out') from None


def report_signatures(path):
    try:
        if path.stat().st_size > REPORT_LIMIT:
            raise ValueError()
        report = json.loads(path.read_text())
        if not isinstance(report, list) or len(report) > 1024:
            raise ValueError()
        result = []
        for finding in report:
            # Report is redacted even though every input is synthetic.
            if not isinstance(finding, dict):
                raise ValueError()
            if finding.get('Secret') != 'REDACTED':
                raise ValueError()
            row = tuple(finding[key] for key in ('RuleID', 'File', 'StartLine', 'EndLine', 'StartColumn', 'EndColumn'))
            if not all(type(v) is int and v > 0 for v in row[2:]):
                raise ValueError()
            if not all(isinstance(v, str) for v in row[:2]):
                raise ValueError()
            result.append(row)
        return sorted(result)
    except (OSError, ValueError, KeyError, TypeError):
        raise FixtureError('invalid or unredacted fixture report') from None


def verify(scanner, config):
    scanner = Path(scanner).resolve(strict=True)
    config = Path(config).resolve(strict=True)
    identity = hashlib.sha256(scanner.read_bytes()).hexdigest()
    files = fixture_files()
    expected = expected_findings(files)
    with tempfile.TemporaryDirectory(prefix='scanner-fixtures-') as directory:
        root = Path(directory)
        for path, content in files.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        for args in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                      '-c', 'commit.gpgsign=false', 'commit', '-qm', 'synthetic scanner fixtures']):
            if run_quiet(['git', *args], root) != 0:
                raise FixtureError('fixture repository setup failed')
        report = root / 'report.json'
        started = time.monotonic()
        code = run_quiet([str(scanner), 'git', '--config', str(config), '--redact', '--no-banner',
                          '--report-format', 'json', '--report-path', str(report),
                          '--log-opts=--full-history --all --diff-filter=tuxdb'], root)
        elapsed = time.monotonic() - started
        if code != 1:
            raise FixtureError('fixture scanner did not return expected findings status')
        actual = report_signatures(report)
        if actual != expected:
            raise FixtureError('fixture finding coverage mismatch')
    return {'schema': 1, 'status': 'success', 'authorityClaim': False, 'reuseEligible': False,
            'engine_sha256': identity, 'config_sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
            'findings': len(expected), 'fixture_bytes': sum(len(v.encode()) for v in files.values()),
            'elapsed_seconds': round(elapsed, 3)}, actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scanner', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--reference')
    args = parser.parse_args()
    try:
        summary, actual = verify(args.scanner, args.config)
        if args.reference:
            reference, other = verify(args.reference, args.config)
            if actual != other:
                raise FixtureError('engine differential mismatch')
            summary['reference'] = reference
        print(json.dumps(summary, sort_keys=True))
        return 0
    except (FixtureError, OSError):
        print('scanner-fixtures: verification failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
