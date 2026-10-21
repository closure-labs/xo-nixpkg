#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Download public bytes into a disposable store and verify hashes and signatures."""
import argparse
import json
import re
from pathlib import Path
import tempfile
import sys
import common
import operations

UPSTREAM_CACHES = ('https://cache.nixos.org',)
UPSTREAM_KEYS = ('cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=',)


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
    _, records = common.ledger(cfg)
    candidates = []
    for proposal in records.values():
        if proposal['kind'] != 'release-product':
            continue
        product = proposal['payload']['product']
        _, active = common.active_release(cfg, records, product, authenticate=False)
        if active != proposal or proposal['payload']['disposition'] != 'accepted':
            continue
        common.historical_provenance(cfg, proposal)
        candidates.append(proposal)
    common.require(candidates, 'No admitted consumer product')
    selected = max(candidates, key=lambda p: (p['payload']['packet']['producer']['runId'],
                                             p['payload']['packet']['producer']['runAttempt']))
    common.emit(probe(selected['payload']['product'], args.cache, args.key))


if __name__ == '__main__':
    sys.exit(common.run(main))
