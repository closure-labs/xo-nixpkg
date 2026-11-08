#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Download public bytes into a disposable store and verify hashes and signatures."""
import argparse
import json
import os
import re
from pathlib import Path
import tempfile
import sys
import common
import operations
import publication_receipts

UPSTREAM_CACHES = ('https://cache.nixos.org',)
UPSTREAM_KEYS = ('cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=',)


def current_product(cfg, records):
    """Choose one exact target before inspecting its complete decision graph.

    Ranking is only a selector, never authority. Do not fall back to older bytes
    when the newest identity is ambiguous, revoked, or not yet published.
    """
    ranked = []
    for proposal in records.values():
        if proposal['kind'] != 'release-product':
            continue
        producer = proposal['payload'].get('packet', {}).get('producer', {})
        common.require(all(type(producer.get(k)) is int and producer[k] > 0
                           for k in ('runId', 'runAttempt')),
                       'Consumer target requires exact qualification ordering')
        ranked.append(((producer['runId'], producer['runAttempt']), proposal['payload']['product']))
    common.require(ranked, 'No admitted consumer product')
    newest = max(rank for rank, _ in ranked)
    products = {common.canonical_hash(product): product for rank, product in ranked if rank == newest}
    common.require(len(products) == 1, 'Ambiguous current consumer product')
    product = next(iter(products.values()))
    _, selected = common.active_release(cfg, records, product, authenticate=False)
    common.require(selected is not None and selected['payload']['disposition'] == 'accepted',
                   'Current consumer product is not accepted')
    common.historical_provenance(cfg, selected)
    return selected


def publication_snapshot(cfg, product, api=None):
    """Require exact completed destination receipts; they do not grant approval."""
    api = api or common.authority.github_api
    digest = common.canonical_hash(product)
    branch = 'automation/publication-' + digest
    endpoint = f'repos/{cfg["repository"]}/git/ref/heads/{branch}'
    ref = api(endpoint)
    revision = ref.get('object', {}).get('sha')
    common.require(ref.get('ref') == 'refs/heads/' + branch
                   and ref.get('object', {}).get('type') == 'commit'
                   and isinstance(revision, str) and common.SHA.fullmatch(revision),
                   'Exact consumer publication journal required')
    tree = api(f'repos/{cfg["repository"]}/git/trees/{revision}')
    entries = tree.get('tree', [])
    common.require(tree.get('truncated') is False and len(entries) == 1
                   and entries[0].get('path') == 'journal.json'
                   and entries[0].get('type') == 'blob' and entries[0].get('mode') == '100644',
                   'Consumer journal must contain one regular immutable document')
    document = common.authority.document_blob(api, cfg['repository'], entries[0].get('sha'),
                                             entries[0].get('size'))
    receipts = publication_receipts.read(document, digest)
    steps = document.get('steps', [])
    common.require(isinstance(steps, list)
                   and all(isinstance(s, dict) for s in steps)
                   and len({s.get('name') for s in steps}) == len(steps),
                   'Ambiguous consumer publication steps')
    completed = {s['name']: s for s in steps if s.get('state') == 'complete'}
    common.require({'cache', 'handoff'} <= set(receipts) & set(completed),
                   'Current consumer product needs completed publication receipts')
    roots = {}
    for entry in [*product['products'].values(), *product.get('roots', {}).values()]:
        path, nar_hash = entry['storePath'], entry['narHash']
        common.require(path not in roots or roots[path] == nar_hash, 'Conflicting consumer roots')
        roots[path] = nar_hash
    common.require(receipts['cache']['expected'] == roots
                   and completed['cache'].get('identity') == {
                       'products': product['products'], 'roots': product.get('roots', {})},
                   'Consumer cache receipt differs from exact approved product')
    handoff = receipts['handoff']['expected']
    producer = handoff.get('producer', {})
    common.require(completed['handoff'].get('identity') == handoff
                   and producer.get('repository') == cfg['repository']
                   and producer.get('sourceRevision') == product['revision']
                   and producer.get('workflow') in cfg['producerWorkflows']
                   and isinstance(producer.get('revision'), str)
                   and common.SHA.fullmatch(producer['revision'])
                   and all(type(producer.get(k)) is int and producer[k] > 0
                           for k in ('runId', 'runAttempt'))
                   and re.fullmatch(re.escape('ghcr.io/' + cfg['repository'].lower() + '-products')
                                    + r'@sha256:[0-9a-f]{64}', handoff.get('reference', ''))
                   and isinstance(handoff.get('sha256'), str)
                   and common.HASH.fullmatch(handoff['sha256']),
                   'Consumer handoff receipt differs from exact published source')
    return endpoint, revision


def unchanged(cfg, main, journal, api=None):
    api = api or common.authority.github_api
    common.require(common.main_revision(cfg, api) == main,
                   'Consumer selection changed on current main; retry from fresh evidence')
    common.require(api(journal[0]).get('object', {}).get('sha') == journal[1],
                   'Consumer publication changed; retry from fresh evidence')


def probe(product, cache, public_key, execute=operations.run):
    entries = [*product['products'].values(), *product.get('roots', {}).values()]
    expected = {}
    for entry in entries:
        path, digest = entry['storePath'], entry['narHash']
        common.require(isinstance(path,str) and re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+',path)
                       and not path.endswith('.drv'), 'Consumer roots must be output paths')
        common.require(path not in expected or expected[path] == digest, 'Conflicting consumer roots')
        expected[path] = digest
    common.require(expected, 'Consumer probe needs exact approved roots')
    paths = sorted(expected)
    with tempfile.TemporaryDirectory(prefix='public-consumer-') as temporary:
        store = 'local?root=' + temporary
        options = ['--option', 'trusted-public-keys', ' '.join((public_key, *UPSTREAM_KEYS)),
                   '--option', 'require-sigs', 'true',
                   '--option', 'substituters', ' '.join((cache, *UPSTREAM_CACHES)),
                   '--option', 'max-jobs', '0', '--option', 'builders', '',
                   '--option', 'substitute', 'true', '--option', 'fallback', 'false',
                   '--option', 'narinfo-cache-positive-ttl', '0', '--option', 'narinfo-cache-negative-ttl', '0']
        # Cachix omits paths available upstream. Substitute into an empty store
        # using exactly the pinned public caches/keys, never the runner's store or
        # a local/remote builder. Input derivations are explicitly rejected.
        execute(['nix-store', '--realise', '--store', store, *options, *paths],
                check=True, capture_output=True, timeout=900)
        execute(['nix', 'store', 'verify', '--store', store, '--recursive', '--sigs-needed', '1',
                 *options, *paths], check=True, capture_output=True, timeout=600)
        result = execute(['nix', 'path-info', '--store', store, '--json', *paths],
                         check=True, capture_output=True, text=True, timeout=120)
        records = json.loads(result.stdout)
        if isinstance(records, list):
            common.require(len({r['path'] for r in records}) == len(records), 'Duplicate consumer roots')
            records = {r['path']: r for r in records}
        common.require(isinstance(records, dict) and set(records) == set(expected)
                       and all(records[path].get('narHash') == digest for path, digest in expected.items()),
                       'Downloaded public NARs differ from approved product')
    return {'schema': 1, 'status': 'verified', 'productHash': common.canonical_hash(product),
            'roots': len(paths), 'downloadedBytesVerified': True, 'signaturesVerified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--cache', required=True)
    parser.add_argument('--key', required=True)
    args = parser.parse_args()
    cfg = common.config(args.config, live=True)
    revision, records, policy = common.ledger(cfg, with_policy=True)
    common.require(common.canonical_hash(policy) == common.canonical_hash(cfg),
                   'Consumer policy changed during selection')
    selected = current_product(cfg, records)
    journal = publication_snapshot(cfg, selected['payload']['product'])
    unchanged(cfg, revision, journal)
    result = probe(selected['payload']['product'], args.cache, args.key)
    unchanged(cfg, revision, journal)
    result['proposalHash'] = common.canonical_hash(selected)
    if os.environ.get('RUNNER_TEMP'):
        common.emit(result, Path(os.environ['RUNNER_TEMP']) / 'public-consumer-result.json')
    else:
        common.emit(result)


if __name__ == '__main__':
    sys.exit(common.run(main))
