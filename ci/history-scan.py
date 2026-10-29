#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exhaustively scan a frozen full-history inventory with bounded work units."""
import concurrent.futures
from contextvars import copy_context
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
sys.path.insert(0, str(Path(__file__).with_name('decisions')))
import operations

SHA = re.compile(r'[0-9a-f]{40}')
MAX_INVENTORY_BYTES = 8 * 1024 * 1024
MAX_COMMITS = 100000
BATCH_SIZE = 8
WORKERS = 2
BATCH_TIMEOUT = 600
TOTAL_TIMEOUT = 1200


def git_lines(root, args, environment):
    def bound():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_INVENTORY_BYTES, MAX_INVENTORY_BYTES))
    with tempfile.TemporaryFile() as output:
        result = operations.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(root), *args],
                                env=environment, stdout=output, stderr=subprocess.DEVNULL,
                                timeout=60, preexec_fn=bound)
        if result.returncode or output.tell() >= MAX_INVENTORY_BYTES:
            raise ValueError('History inventory failed or exceeded bound')
        output.seek(0)
        return [line.decode('utf-8', errors='surrogateescape') for line in output.read().split(b'\n') if line]


def refs(root, environment):
    # Include HEAD exactly as Git's default --all does, as well as every ref.
    rows = git_lines(root, ['for-each-ref', '--format=%(objectname) %(refname)'], environment)
    head = git_lines(root, ['rev-parse', '--verify', 'HEAD'], environment)
    if len(head) != 1 or not SHA.fullmatch(head[0]):
        raise ValueError('Invalid history HEAD')
    for row in rows:
        identity, separator, name = row.partition(' ')
        if not separator or not SHA.fullmatch(identity) or not name.startswith('refs/'):
            raise ValueError('Invalid history ref inventory')
    # Git --all also includes detached HEADs of linked worktrees. Paths are
    # deliberately not retained in telemetry; only their immutable tips matter.
    worktrees = git_lines(root, ['worktree', 'list', '--porcelain'], environment)
    tips = []
    for row in worktrees:
        if row.startswith('HEAD '):
            identity = row[5:]
            if not SHA.fullmatch(identity):
                raise ValueError('Invalid worktree history HEAD')
            tips.append(identity + ' WORKTREE_HEAD')
    return sorted(set(rows + [head[0] + ' HEAD'] + tips))


def inventory(root, environment):
    if git_lines(root, ['rev-parse', '--is-shallow-repository'], environment) != ['false']:
        raise ValueError('History security scan requires a complete Git checkout')
    snapshot = refs(root, environment)
    # --stdin avoids argv limits while all tips remain immutable object IDs.
    tips = '\n'.join(sorted({row.split(' ')[0] for row in snapshot})) + '\n'
    with tempfile.TemporaryFile() as output:
        def bound():
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_INVENTORY_BYTES, MAX_INVENTORY_BYTES))
        result = operations.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(root),
                                 'rev-list', '--full-history', '--stdin'], input=tips.encode(),
                                stdout=output, stderr=subprocess.DEVNULL, env=environment,
                                timeout=60, preexec_fn=bound)
        if result.returncode or output.tell() >= MAX_INVENTORY_BYTES:
            raise ValueError('Complete history enumeration failed or exceeded bound')
        output.seek(0)
        commits = output.read().decode('ascii').splitlines()
    if (not commits or len(commits) > MAX_COMMITS or len(set(commits)) != len(commits)
            or any(not SHA.fullmatch(commit) for commit in commits)):
        raise ValueError('Invalid complete commit inventory')
    return snapshot, sorted(commits)


def scan(root, environment=None, scanner='gitleaks'):
    environment = dict(os.environ if environment is None else environment)
    started = time.monotonic()
    with operations.budget(TOTAL_TIMEOUT):
        snapshot, commits = inventory(root, environment)
        batches = [commits[i:i + BATCH_SIZE] for i in range(0, len(commits), BATCH_SIZE)]
        # Prove partition completeness before invoking scanners.
        if [c for batch in batches for c in batch] != commits:
            raise ValueError('Incomplete history partition')
        def execute(item):
            index, batch = item
            begin = time.monotonic()
            # Identical Git patch/filter defaults, but no traversal from the
            # explicit commits: ancestors are present exactly once elsewhere.
            options = '--no-walk=unsorted --full-history --diff-filter=tuxdb ' + ' '.join(batch)
            def blocked(reason):
                print(json.dumps({'schema': 1, 'stage': 'history-batch', 'status': 'blocked',
                                  'batch': index, 'commits': len(batch), 'reason': reason,
                                  'seconds': round(time.monotonic() - begin, 3)}, sort_keys=True), flush=True)
            try:
                result = operations.run([scanner, 'git', '--redact', '--no-banner', '--log-opts=' + options],
                                        cwd=root, env=environment, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=BATCH_TIMEOUT)
            except subprocess.TimeoutExpired:
                blocked('timeout')
                raise
            except OSError:
                blocked('scanner-start-failed')
                raise
            # Scanner output may contain secrets even in failure diagnostics.
            # Publish only fixed categories and counters, never raw output.
            if result.returncode:
                blocked('findings-or-scanner-error')
                raise ValueError('History scan batch failed (findings or scanner error)')
            return index, len(batch), round(time.monotonic() - begin, 3)
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            pending = {}
            iterator = iter(enumerate(batches))
            def submit():
                item = next(iterator, None)
                if item is not None:
                    pending[pool.submit(copy_context().run, execute, item)] = item[0]
            for _ in range(WORKERS):
                submit()
            while pending:
                operations.remaining(TOTAL_TIMEOUT)
                done, _ = concurrent.futures.wait(pending, timeout=1,
                                                  return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    index, count, elapsed = future.result()
                    if index != pending.pop(future) or index in results:
                        raise ValueError('Invalid history batch coverage')
                    results[index] = (count, elapsed)
                    submit()
        if (set(results) != set(range(len(batches)))
                or sum(count for count, _ in results.values()) != len(commits)
                or refs(root, environment) != snapshot):
            raise ValueError('Incomplete or changed history scan coverage')
        return {'schema': 1, 'status': 'success', 'commits': len(commits), 'batches': len(batches),
                'inventorySha256': hashlib.sha256(('\n'.join(commits) + '\n').encode()).hexdigest(),
                'seconds': round(time.monotonic() - started, 3),
                'maximumBatchSeconds': max(elapsed for _, elapsed in results.values())}


def main():
    try:
        print(json.dumps(scan(Path.cwd()), sort_keys=True))
        return 0
    except (ValueError, OSError, UnicodeError, subprocess.SubprocessError):
        print(json.dumps({'schema': 1, 'status': 'blocked',
                          'reason': 'Full history scan failed, timed out, or has incomplete coverage'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
