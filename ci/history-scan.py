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
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
sys.path.insert(0, str(Path(__file__).with_name('decisions')))
import operations

SHA = re.compile(r'[0-9a-f]{40}')
MAX_INVENTORY_BYTES = 8 * 1024 * 1024
MAX_COMMITS = 100000
BATCH_SIZE = 8
WORKERS = 2
BATCH_TIMEOUT = 600
TOTAL_TIMEOUT = 1200
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_POLICY_BYTES = 8 * 1024 * 1024


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


def file_digest(path, maximum=None):
    if not path.is_file():
        raise ValueError('Scan identity file is not regular')
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        while chunk := stream.read(65536):
            size += len(chunk)
            if maximum is not None and size > maximum:
                raise ValueError('Scan identity file exceeds bound')
            digest.update(chunk)
    return digest.hexdigest()


def policy_identity(root):
    result = {}
    for name in ('.gitleaks.toml', '.gitleaksignore'):
        path = Path(root) / name
        if path.is_symlink():
            raise ValueError('Scan policy must not be a symlink')
        result[name] = file_digest(path, MAX_POLICY_BYTES) if path.exists() else None
    return result


def production_scanner(environment):
    scanner = environment.get('XO_NIXPKG_SECRET_SCANNER', '')
    metadata_path = environment.get('XO_NIXPKG_SECRET_SCANNER_IDENTITY', '')
    if (not re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/]+/bin/gitleaks', scanner)
            or not re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/]+', metadata_path)):
        raise ValueError('Pinned scanner identity is required')
    path = Path(metadata_path)
    if not path.is_file() or path.is_symlink():
        raise ValueError('Pinned scanner metadata must be a regular store file')
    with path.open('rb') as stream:
        raw = stream.read(4097)
    if not raw or len(raw) > 4096:
        raise ValueError('Pinned scanner metadata exceeds bound')
    identity = json.loads(raw)
    if (not isinstance(identity, dict) or identity.get('schema') != 1
            or identity.get('name') != 'gitleaks' or identity.get('version') != '8.30.1'
            or identity.get('regexpEngine') != 'go-stdlib'
            or identity.get('executable') != scanner
            or not Path(scanner).is_file() or Path(scanner).is_symlink()
            or not os.access(scanner, os.X_OK)):
        raise ValueError('Pinned scanner identity does not match')
    if any(environment.get(key) for key in ('GITLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML')):
        raise ValueError('External scanner policy override is not supported')
    # Never echo arbitrary caller-supplied fields into diagnostic telemetry.
    metadata = {key: identity[key] for key in
                ('schema', 'name', 'version', 'regexpEngine', 'executable')}
    metadata['metadataSha256'] = hashlib.sha256(raw).hexdigest()
    return scanner, metadata


def scan(root, environment=None, scanner='gitleaks', scanner_identity=None):
    environment = dict(os.environ if environment is None else environment)
    started = time.monotonic()
    with operations.budget(TOTAL_TIMEOUT):
        scanner_path = shutil.which(scanner, path=environment.get('PATH'))
        scanner_hash = file_digest(Path(scanner_path)) if scanner_path else None
        if scanner_identity is not None and scanner_hash is None:
            raise ValueError('Pinned scanner executable unavailable')
        policy = policy_identity(root)
        if scanner_identity is not None and policy['.gitleaks.toml'] is not None:
            with (Path(root) / '.gitleaks.toml').open('rb') as stream:
                policy_bytes = stream.read(MAX_POLICY_BYTES + 1)
            if (len(policy_bytes) > MAX_POLICY_BYTES
                    or hashlib.sha256(policy_bytes).hexdigest() != policy['.gitleaks.toml']):
                raise ValueError('Scanner policy changed before execution')
            config = tomllib.loads(policy_bytes.decode('utf-8'))
            for key, extension in config.items():
                if key.casefold() == 'extend' and (
                        not isinstance(extension, dict)
                        or any(name.casefold() == 'path' for name in extension)):
                    raise ValueError('External scanner policy extension is not supported')
        helper_hash = file_digest(Path(__file__))
        git_version = git_lines(root, ['--version'], environment)
        if len(git_version) != 1 or not re.fullmatch(r'git version [0-9A-Za-z.+-]{1,80}', git_version[0]):
            raise ValueError('Invalid Git version identity')
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
        if (policy_identity(root) != policy or file_digest(Path(__file__)) != helper_hash
                or (scanner_path and file_digest(Path(scanner_path)) != scanner_hash)):
            raise ValueError('Scan identity changed during execution')
        receipt = {'schema': 1, 'authorityClaim': False, 'reuseEligible': False,
                   'coverage': 'complete-frozen-all-refs-and-worktree-heads',
                   'commitIds': commits,
                   'refs': [{'object': row.partition(' ')[0],
                             'nameSha256': hashlib.sha256(row.partition(' ')[2].encode(
                                 'utf-8', errors='surrogateescape')).hexdigest()}
                            for row in snapshot],
                   'scanner': {'executableSha256': scanner_hash,
                               'identity': scanner_identity,
                               'productionPinned': scanner_identity is not None},
                   'policySha256': policy, 'helperSha256': helper_hash,
                   'gitVersion': git_version[0],
                   'semantics': {'enumeration': 'rev-list --full-history --stdin',
                                 'patch': '--no-walk=unsorted --full-history --diff-filter=tuxdb',
                                 'scanner': 'git --redact --no-banner',
                                 'incrementalReuse': False}}
        if len(json.dumps(receipt, sort_keys=True).encode()) > MAX_RECEIPT_BYTES:
            raise ValueError('History receipt exceeds bound')
        return {'schema': 1, 'status': 'success', 'authorityClaim': False, 'reuseEligible': False, 'receipt': receipt, 'commits': len(commits), 'batches': len(batches),
                'inventorySha256': hashlib.sha256(('\n'.join(commits) + '\n').encode()).hexdigest(),
                'seconds': round(time.monotonic() - started, 3),
                'maximumBatchSeconds': max(elapsed for _, elapsed in results.values())}


def main():
    try:
        scanner, identity = production_scanner(os.environ)
        print(json.dumps(scan(Path.cwd(), scanner=scanner, scanner_identity=identity), sort_keys=True))
        return 0
    except (ValueError, OSError, UnicodeError, subprocess.SubprocessError):
        print(json.dumps({'schema': 1, 'status': 'blocked', 'authorityClaim': False, 'reuseEligible': False,
                          'reason': 'Full history scan failed, timed out, or has incomplete coverage'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
