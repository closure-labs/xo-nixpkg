#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Mirror one Dependabot-selected nixpkgs identity; never evaluate PR code.

Runs only from protected main. GETs use a read-only token. The optional writer
uses a separately scoped App token, creates a single-parent commit, and never
forces a ref, retries an uncertain mutation, approves, or dequeues a PR.
"""
import argparse
import base64
import copy
import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys

REPO = 'closure-labs/xo-nixpkg'
SHA = re.compile(r'[0-9a-f]{40}')
LIMIT = 1024 * 1024


def require(test, message):
    if not test:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def parse(raw):
    require(isinstance(raw, bytes) and len(raw) <= LIMIT, 'Lockfile exceeds bound')
    return json.loads(raw, object_pairs_hook=unique)


def node(lock):
    require(isinstance(lock, dict) and set(lock) == {'nodes', 'root', 'version'}
            and lock['version'] == 7 and lock['root'] == 'root', 'Unsupported lock schema')
    nodes = lock['nodes']
    require(isinstance(nodes, dict) and 1 < len(nodes) <= 128, 'Invalid lock nodes')
    root = nodes.get('root')
    require(isinstance(root, dict) and set(root) == {'inputs'} and isinstance(root['inputs'], dict),
            'Invalid root inputs')
    name = root['inputs'].get('nixpkgs')
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*', name)
            and name in nodes, 'Unsupported nixpkgs input path')
    value = nodes[name]
    require(isinstance(value, dict) and set(value) == {'locked', 'original'}, 'Unexpected nixpkgs node')
    require(value['original'] == {'owner': 'NixOS', 'repo': 'nixpkgs', 'ref': 'nixos-unstable', 'type': 'github'},
            'Unexpected nixpkgs source')
    locked = value['locked']
    require(isinstance(locked, dict) and set(locked) == {'owner', 'repo', 'type', 'rev', 'narHash', 'lastModified'}
            and locked['owner'] == 'NixOS' and locked['repo'] == 'nixpkgs' and locked['type'] == 'github'
            and isinstance(locked['rev'], str) and SHA.fullmatch(locked['rev'])
            and isinstance(locked['narHash'], str) and re.fullmatch(r'sha256-[A-Za-z0-9+/]{43}=', locked['narHash'])
            and type(locked['lastModified']) is int and locked['lastModified'] >= 0, 'Invalid nixpkgs locked identity')
    return name, value


def synchronize(base_flake, candidate_flake, base_devenv, candidate_devenv):
    old, new, native, candidate_native = map(parse, (base_flake, candidate_flake, base_devenv, candidate_devenv))
    old_name, old_node = node(old)
    new_name, new_node = node(new)
    native_name, native_node = node(native)
    node(candidate_native)
    require(old_node == native_node, 'Protected lock pair is inconsistent')
    require(old_name == new_name, 'Input node renamed')
    expected_flake = copy.deepcopy(old)
    expected_flake['nodes'][old_name]['locked'] = new_node['locked']
    require(expected_flake == new and old_node != new_node, 'Candidate is not solely a nixpkgs lock update')
    require(old_node['locked']['rev'] != new_node['locked']['rev'], 'Nixpkgs revision did not change')
    expected_native = copy.deepcopy(native)
    expected_native['nodes'][native_name]['locked'] = copy.deepcopy(new_node['locked'])
    require(candidate_native in (native, expected_native), 'Candidate altered unrelated native inputs')
    return None if candidate_native == expected_native else (json.dumps(expected_native, indent=2) + '\n').encode()


def request(endpoint, body=None, method=None):
    env = dict(os.environ)
    if body is None:
        env['GH_TOKEN'] = os.environ['REPOSITORY_READ_TOKEN']
    args = ['gh', 'api', 'graphql' if endpoint == 'graphql' else 'repos/' + REPO + '/' + endpoint]
    if body is not None:
        args += ['--method', method or 'POST', '--input', '-']
    result = subprocess.run(args, input=json.dumps(body) if body is not None else None,
                            env=env, text=True, capture_output=True, timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 4 * LIMIT, 'GitHub operation failed; inspect state before retry')
    return json.loads(result.stdout)


def pr_identity(pr, number, base, head):
    require(pr.get('number') == number and pr.get('state') == 'open' and pr.get('merged') is False,
            'PR must remain open and unmerged')
    user = pr.get('user', {})
    require(user.get('id') == 49699333 and user.get('login') == 'dependabot[bot]' and user.get('type') == 'Bot',
            'Only native Dependabot PRs are supported')
    branch = pr.get('head', {}).get('ref', '')
    require(re.fullmatch(r'dependabot/nix/[A-Za-z0-9][A-Za-z0-9._/-]*', branch)
            and '..' not in branch and not branch.endswith(('/', '.lock')), 'Unexpected Dependabot branch')
    require(pr.get('base', {}).get('ref') == 'main' and pr['base'].get('sha') == base
            and pr.get('head', {}).get('sha') == head
            and all(pr.get(part, {}).get('repo', {}).get('full_name') == REPO for part in ('base', 'head')),
            'PR base, head, or repository changed')
    require(type(pr.get('changed_files')) is int and 1 <= pr['changed_files'] <= 2, 'Unexpected changed file count')
    return branch


def plan(number, base, head, api=request):
    require(SHA.fullmatch(base) and SHA.fullmatch(head), 'Invalid immutable inputs')
    def current():
        ref = api('git/ref/heads/main')
        require(ref.get('ref') == 'refs/heads/main' and ref.get('object', {}).get('type') == 'commit'
                and ref['object'].get('sha') == base, 'Protected main advanced; rebase first')
        return api(f'pulls/{number}')
    pr = current()
    branch = pr_identity(pr, number, base, head)
    files = api(f'pulls/{number}/files?per_page=100')
    require(isinstance(files, list) and len(files) == pr['changed_files']
            and {item.get('filename') for item in files} in ({'flake.lock'}, {'flake.lock', 'devenv.lock'})
            and all(item.get('status') == 'modified' and 'previous_filename' not in item for item in files),
            'Unexpected candidate paths or change types')
    trees = {}
    def contents(path, revision):
        if revision not in trees:
            commit = api('git/commits/' + revision)
            tree_sha = commit.get('tree', {}).get('sha')
            require(commit.get('sha') == revision and isinstance(tree_sha, str) and SHA.fullmatch(tree_sha),
                    'Invalid immutable commit tree')
            tree = api('git/trees/' + tree_sha)
            require(tree.get('sha') == tree_sha and tree.get('truncated') is False
                    and isinstance(tree.get('tree'), list), 'Incomplete immutable tree')
            trees[revision] = tree['tree']
        entries = [entry for entry in trees[revision] if entry.get('path') == path]
        require(len(entries) == 1 and entries[0].get('mode') == '100644'
                and entries[0].get('type') == 'blob', 'Lock must be an ordinary non-executable file')
        value = api('contents/' + path + '?ref=' + revision)
        require(value.get('type') == 'file' and value.get('path') == path and value.get('encoding') == 'base64'
                and type(value.get('size')) is int and 0 < value['size'] <= LIMIT, 'Invalid lockfile blob')
        raw = base64.b64decode(value['content'], validate=False)
        digest = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        require(len(raw) == value['size'] and value.get('sha') == digest == entries[0].get('sha'),
                'Lockfile blob identity mismatch')
        return raw
    output = synchronize(contents('flake.lock', base), contents('flake.lock', head),
                         contents('devenv.lock', base), contents('devenv.lock', head))
    require(pr_identity(current(), number, base, head) == branch, 'PR changed during planning')
    return branch, output


def execute(number, base, head, api=request):
    branch, content = plan(number, base, head, api)
    if content is None:
        return {'changed': False}
    # createCommitOnBranch is an atomic compare-and-swap at expectedHeadOid.
    # Unlike a force=false REST ref update, it also rejects concurrent rewinds.
    require(plan(number, base, head, api) == (branch, content), 'Candidate changed before write')
    mutation = """mutation($input: CreateCommitOnBranchInput!) {
      createCommitOnBranch(input: $input) { commit { oid } }
    }"""
    result = api('graphql', {'query': mutation, 'variables': {'input': {
        'branch': {'repositoryNameWithOwner': REPO, 'branchName': branch},
        'expectedHeadOid': head,
        'message': {'headline': 'Synchronize native nixpkgs lock with Dependabot selection [dependabot skip]'},
        'fileChanges': {'additions': [{'path': 'devenv.lock',
                                     'contents': base64.b64encode(content).decode()}]}}}})
    require(not result.get('errors'), 'Commit rejected or uncertain; inspect state before retry')
    sha = result.get('data', {}).get('createCommitOnBranch', {}).get('commit', {}).get('oid')
    require(isinstance(sha, str) and SHA.fullmatch(sha), 'Commit unconfirmed; inspect state before retry')
    # A successful mutation response is not a complete publication receipt.
    # Verify via read-only REST; uncertainty fails without another mutation.
    receipt = api('commits/' + sha)
    require(receipt.get('sha') == sha
            and [p.get('sha') for p in receipt.get('parents', [])] == [head]
            and receipt.get('author', {}).get('login') == 'cl-decider[bot]'
            and receipt.get('author', {}).get('type') == 'Bot'
            and receipt.get('commit', {}).get('verification', {}).get('verified') is True
            and receipt['commit']['verification'].get('reason') == 'valid',
            'Commit authorship, signature, or parent unconfirmed; inspect state before retry')
    def tree_map(revision):
        commit = api('git/commits/' + revision)
        require(commit.get('sha') == revision, 'Receipt commit identity mismatch')
        tree_sha = commit.get('tree', {}).get('sha')
        require(isinstance(tree_sha, str) and SHA.fullmatch(tree_sha), 'Receipt tree identity missing')
        tree = api('git/trees/' + tree_sha)
        require(tree.get('sha') == tree_sha and tree.get('truncated') is False
                and isinstance(tree.get('tree'), list), 'Receipt tree incomplete')
        entries = tree['tree']
        require(all(isinstance(e.get('path'), str) for e in entries)
                and len({e['path'] for e in entries}) == len(entries), 'Receipt tree malformed')
        return {e['path']: (e.get('mode'), e.get('type'), e.get('sha')) for e in entries}
    before, after = tree_map(head), tree_map(sha)
    expected = dict(before)
    digest = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
    expected['devenv.lock'] = ('100644', 'blob', digest)
    require(after == expected, 'Commit tree delta unconfirmed; inspect state before retry')
    return {'changed': True, 'head': sha}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    require(os.environ.get('GITHUB_REPOSITORY') == REPO, 'Unexpected repository')
    base = os.environ['EXPECTED_BASE']
    local = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    require(local == base, 'Controller must be exact protected base')
    number = int(os.environ['PR_NUMBER'])
    require(number > 0, 'Invalid PR number')
    head = os.environ['EXPECTED_HEAD']
    result = execute(number, base, head) if args.write else {'changed': plan(number, base, head)[1] is not None}
    print(json.dumps(result, sort_keys=True))
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('changed=' + str(result['changed']).lower() + '\n')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        print('Lock synchronization refused; inspect current PR state and inputs', file=sys.stderr)
        sys.exit(1)
