#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded hosted scanner triage: emit location metadata, never finding values."""
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import subprocess
import sys
import tempfile

REPO = 'closure-labs/xo-nixpkg'
FILES = frozenset(('.github/workflows/compare-retained-nars.yml', '.github/workflows/diagnostic-secret-triage.yml',
                   'ci/compare-retained-nars.py', 'ci/diagnostic-secret-triage.py', 'ci/classifier.json',
                   'tests/test_retained_nar_comparison.py', 'tests/test_diagnostic_secret_triage.py',
                   'docs/retained-nar-comparison.md'))


class Blocked(ValueError):
    pass


def require(value, code):
    if not value:
        raise Blocked(code)


def sanitize(value, commits):
    require(isinstance(value, list) and len(value) <= 1000, 'finding-inventory-bound')
    rows = []
    for finding in value:
        require(isinstance(finding, dict), 'finding-schema')
        rule, file, line, commit = (finding.get(k) for k in ('RuleID', 'File', 'StartLine', 'Commit'))
        require(isinstance(rule, str) and re.fullmatch('[a-z0-9][a-z0-9-]{0,80}', rule), 'rule-schema')
        require(isinstance(file, str) and file in FILES and str(PurePosixPath(file)) == file, 'finding-file-not-allowlisted')
        require(type(line) is int and 0 < line <= 1000000, 'line-schema')
        require(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}', commit) and commit in commits, 'finding-commit-binding')
        rows.append({'rule': rule, 'file': file, 'line': line, 'commit': commit})
    return rows


def main():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == REPO, 'hosted-context')
    base, head = os.environ['BASE_SHA'], os.environ['HEAD_SHA']
    require(re.fullmatch('[0-9a-f]{40}', base) and re.fullmatch('[0-9a-f]{40}', head) and base != head, 'range-schema')
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:1])
    def limits():
        resource.setrlimit(resource.RLIMIT_AS, (3*1024**3, 3*1024**3))
        resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
        resource.setrlimit(resource.RLIMIT_FSIZE, (2*1024**2, 2*1024**2))
    def git(*args):
        result = subprocess.run(['git', *args], capture_output=True, timeout=20, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 1024**2, 'git-metadata-failed')
        return result.stdout
    require(git('rev-parse', 'HEAD').decode().strip() == head, 'head-binding')
    commits = set(git('rev-list', base+'..'+head).decode().splitlines())
    require(0 < len(commits) <= 100, 'commit-bound')
    config = git('show', base+':.gitleaks.toml')
    with tempfile.TemporaryDirectory(prefix='private-scanner-triage-') as directory:
        directory = Path(directory); directory.chmod(0o700)
        (directory/'config.toml').write_bytes(config); (directory/'ignore').write_bytes(b'')
        report = directory/'report.json'
        env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'TMPDIR')}
        env.update(GOMAXPROCS='1', GOMEMLIMIT='256MiB')
        process = subprocess.run([sys.argv[1], 'git', '.', '--config', str(directory/'config.toml'),
                                  '--gitleaks-ignore-path', str(directory/'ignore'), '--ignore-gitleaks-allow',
                                  '--redact=100', '--no-banner', '--log-level=error', '--exit-code=2',
                                  '--report-format=json', '--report-path', str(report),
                                  '--log-opts=--full-history --diff-merges=first-parent --text --no-ext-diff --no-textconv '+base+'..'+head],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90,
                                 env=env, preexec_fn=limits, check=False)
        require(process.returncode in (0, 2), 'scanner-runtime-error')
        require(report.is_file() and not report.is_symlink() and report.stat().st_size <= 2*1024**2, 'report-bound')
        rows = sanitize(json.loads(report.read_bytes()), commits)
        require((process.returncode == 2) == bool(rows), 'scanner-result-binding')
        print(json.dumps({'status': 'classified', 'findingValuesEmitted': False, 'findings': rows}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'blocked', 'code': str(error) if type(error) is Blocked else 'triage-failed', 'findingValuesEmitted': False}))
        raise SystemExit(1)
