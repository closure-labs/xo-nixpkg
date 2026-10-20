#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publish admitted immutable products with a compare-and-swap Git ref journal."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def api(repository, endpoint, body=None, method=None, missing=False):
    args = ['gh', 'api', f'repos/{repository}/{endpoint}']
    if body is not None:
        args += ['--method', method or 'POST', '--input', '-']
    result = subprocess.run(args, input=json.dumps(body) if body is not None else None,
                            text=True, capture_output=True, check=False)
    if result.returncode:
        if missing and 'HTTP 404' in result.stderr:
            return None
        raise RuntimeError('GitHub journal API failed: ' + endpoint)
    return json.loads(result.stdout)


class Journal:
    def __init__(self, repository, product):
        self.repository = repository
        self.digest = hashlib.sha256(canonical(product)).hexdigest()
        self.branch = 'automation/publication-' + self.digest
        ref = api(repository, 'git/ref/heads/' + self.branch, missing=True)
        self.commit = ref['object']['sha'] if ref else None
        if self.commit:
            commit = api(repository, 'git/commits/' + self.commit)
            tree = api(repository, 'git/trees/' + commit['tree']['sha'])
            if len(tree['tree']) != 1 or tree['tree'][0]['path'] != 'journal.json':
                raise ValueError('unexpected publication journal tree')
            blob = api(repository, 'git/blobs/' + tree['tree'][0]['sha'])
            import base64
            self.value = json.loads(base64.b64decode(blob['content']))
            if self.value.get('schema') != 1 or self.value.get('productHash') != self.digest:
                raise ValueError('publication journal has conflicting immutable identity')
        else:
            self.value = {'schema': 1, 'productHash': self.digest, 'steps': []}
            self.save()

    def save(self):
        tree = api(self.repository, 'git/trees', {'tree': [{'path': 'journal.json', 'mode': '100644',
            'type': 'blob', 'content': json.dumps(self.value, sort_keys=True, indent=2) + '\n'}]})
        body = {'message': 'Record immutable publication ' + self.digest, 'tree': tree['sha'],
                'parents': [self.commit] if self.commit else []}
        commit = api(self.repository, 'git/commits', body)
        if self.commit:
            # A concurrent writer produces a sibling commit; force=false refuses
            # its non-fast-forward update instead of losing either checkpoint.
            api(self.repository, 'git/refs/heads/' + self.branch, {'sha': commit['sha'], 'force': False}, method='PATCH')
        else:
            api(self.repository, 'git/refs', {'ref': 'refs/heads/' + self.branch, 'sha': commit['sha']})
        live = api(self.repository, 'git/ref/heads/' + self.branch)
        if live['object']['sha'] != commit['sha']:
            raise ValueError('publication journal changed concurrently')
        self.commit = commit['sha']

    def complete(self, name, identity):
        existing = next((step for step in self.value['steps'] if step['name'] == name), None)
        if existing:
            if existing['identity'] != identity and name != 'handoff':
                raise ValueError('conflicting immutable publication step')
            existing.update(state='complete', identity=identity)
        else:
            self.value['steps'].append({'name': name, 'state': 'complete', 'identity': identity})
        self.save()


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def publish_handoff(directory, scans, repository, source_revision):
    """Keep registry credentials scoped while preserving current scan provenance."""
    import decision_packets as packets
    packets.REGISTRY = 'ghcr.io/' + repository.lower() + '-products'
    packets.REFERENCE = re.compile(re.escape(packets.REGISTRY) + r'@sha256:[0-9a-f]{64}')
    registry_token = os.environ['REGISTRY_TOKEN']
    previous_config = os.environ.get('DOCKER_CONFIG')
    try:
        with tempfile.TemporaryDirectory(prefix='xo-publication-registry-') as registry_config:
            os.environ['DOCKER_CONFIG'] = registry_config
            run('oras', 'login', 'ghcr.io', '--username', os.environ['GITHUB_ACTOR'],
                '--password-stdin', input=registry_token, text=True)
            try:
                run('xo-nixpkg-publication-gate')
                producer = dict(scans['producer'], repository=repository,
                                revision=scans['producer'].get('revision', source_revision),
                                sourceRevision=source_revision)
                return packets.push(directory, producer)
            finally:
                run('oras', 'logout', 'ghcr.io')
    finally:
        if previous_config is None:
            os.environ.pop('DOCKER_CONFIG', None)
        else:
            os.environ['DOCKER_CONFIG'] = previous_config


def main():
    directory = Path(os.environ['XO_NIXPKG_EVIDENCE']).resolve()
    product = json.loads((directory / 'product.json').read_text())
    scans = json.loads((directory / 'scans.json').read_text())
    repository, revision = product['repository'], product['revision']
    os.environ['GATED_SHA'] = revision
    os.environ['XO_NIXPKG_PUBLICATION_PURPOSE'] = os.environ.get('XO_NIXPKG_PUBLICATION_PURPOSE', 'release')
    run('xo-nixpkg-publication-gate')
    os.environ['BASE_SHA'] = subprocess.check_output(['git', 'rev-parse', revision + '^'], text=True).strip()
    for name, expected in product['assets'].items():
        path = directory / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('publication asset differs from approved immutable bytes')
    journal = Journal(repository, product)
    run('xo-nixpkg-publish')
    journal.complete('cache', {'products': product['products'], 'roots': product.get('roots', {})})
    # Store independent, attested downstream handoffs indefinitely. The registry
    # module verifies content digests and refuses conflicting immutable tags.
    # Candidate NARs remain in private decision packets until live admission.
    # This packet provides the independently published downstream handoff.
    packet = publish_handoff(directory, scans, repository, revision)
    journal.complete('handoff', packet)
    if os.environ['XO_NIXPKG_PUBLICATION_PURPOSE'] == 'release':
        run('xo-nixpkg-tag-xo-release')
        journal.complete('xo-tag', {'revision': revision})
        version = subprocess.check_output(['git', 'show', revision + ':VERSION'], text=True).strip()
        tag = 'v' + version
        existing = subprocess.run(['git', 'rev-parse', '--verify', tag + '^{commit}'], capture_output=True, text=True)
        # Project versions remain independent from package/cache refreshes.
        if existing.returncode == 0 and existing.stdout.strip() != revision:
            print('Project version already released; package publication is complete.')
        else:
            run('xo-nixpkg-tag-release')
            journal.complete('project-tag', {'tag': tag, 'revision': revision})
            run('xo-nixpkg-publish-release')
            journal.complete('github-release', {'tag': tag, 'revision': revision})
    print(json.dumps({'schema': 1, 'productHash': journal.digest, 'journalRef': journal.branch}))


if __name__ == '__main__':
    main()
