#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Recover exact candidate bytes from private, digest-bound reviewed evidence."""
import json
import os
import sys
import time
import tempfile
from pathlib import Path
import re

import decision_authority as authority
import decision_packets as packets
from common import config

PROPOSAL = re.compile(r'automation/decisions/(security|releases)/[0-9a-f]{64}\.json')


def find_packets(cfg, run_id, attempt):
    repository = cfg['repository']
    revision = authority.github_api(f'repos/{repository}/git/ref/heads/main')['object']['sha']
    tree = authority.github_api(f'repos/{repository}/git/trees/{revision}?recursive=1')
    if tree.get('truncated') is not False:
        raise ValueError('incomplete retained decision inventory')
    candidates = [(item['path'], revision) for item in tree['tree'] if PROPOSAL.fullmatch(item['path'])]
    for pull in authority.collection(authority.github_api, f'repos/{repository}/pulls?state=open&base=main'):
        if pull.get('user', {}).get('login') != cfg['botLogin'] or not pull.get('head', {}).get('ref', '').startswith('automation/decision-'):
            continue
        files = authority.collection(authority.github_api, f'repos/{repository}/pulls/{pull["number"]}/files')
        candidates += [(item['filename'], pull['head']['sha']) for item in files if PROPOSAL.fullmatch(item['filename'])]
    found = {}
    for path, source in candidates:
        document = authority.document_at(authority.github_api, repository, path, source)
        packet = document.get('payload', {}).get('packet', {})
        producer = packet.get('producer', {})
        if producer.get('runId') == run_id and producer.get('runAttempt') == attempt and producer.get('repository') == repository:
            reference, digest = packet.get('reference'), packet.get('sha256')
            if not isinstance(reference, str) or not packets.REFERENCE.fullmatch(reference) or not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest):
                raise ValueError('unsafe retained candidate reference')
            found[(reference, digest)] = packet
    return list(found.values())


def inventory_only(packet, output):
    """Materialize data from the existing immutable descriptor, never NAR layers."""
    import json
    if output.exists():
        raise ValueError('Inventory output must be fresh')
    with packets.operations.budget(300), tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        _, members = packets.inspect(packet['reference'])
        descriptor = packets.packet_descriptor(
            packets.fetch_member('decision-packet.json', directory, members), members, packet['sha256'])
        if descriptor['producer'] != packet['producer']:
            raise ValueError('Inventory descriptor producer mismatch')
        def read(name, limit):
            record = descriptor['files'].get(name)
            if not record or not 0 < record['size'] <= limit:
                raise ValueError('Inventory member missing or oversized')
            return packets.fetch_member(name, directory, members)
        product_path = read('product.json', 16 * 1024**2)
        read('scans.json', 128 * 1024**2)
        product = packets.decode_json(product_path.read_bytes())
        assets = product.get('assets')
        if not isinstance(assets, dict) or not 0 < len(assets) <= 256:
            raise ValueError('Inventory asset manifest missing or oversized')
        total = sum((directory / n).stat().st_size for n in ('product.json', 'scans.json'))
        for name, expected in assets.items():
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.+-]+', name):
                raise ValueError('Unsafe immutable inventory asset')
            record = descriptor['files'].get(name, {})
            if record.get('sha256') != expected:
                raise ValueError('Inventory asset differs from authenticated descriptor')
            size = record.get('size', 0)
            if type(size) is not int or not 0 < size <= 64 * 1024**2:
                raise ValueError('Inventory asset missing or oversized')
            total += size
            if total > 512 * 1024**2:
                raise ValueError('Inventory aggregate exceeds bound')
            read(name, 64 * 1024**2)
        output.mkdir()
        for name in ('product.json', 'scans.json', *assets):
            packets.install_member(directory / name, output / name, output)


def main():
    # These observations explain exact-run fallback; they never select evidence.
    observation = {'schema': 1, 'authorityClaim': False, 'status': 'blocked'}
    started = time.monotonic_ns()
    try:
        return fetch(observation)
    finally:
        if os.environ.get('XO_NIXPKG_PUBLICATION_METADATA_ONLY') == 'true' and os.environ.get('RUNNER_TEMP'):
            observation['elapsedMilliseconds'] = (time.monotonic_ns() - started) // 1_000_000
            try:
                # Replace atomically without following an existing diagnostic link.
                with tempfile.NamedTemporaryFile(mode='w', dir=os.environ['RUNNER_TEMP'], delete=False) as stream:
                    temporary = Path(stream.name)
                    try:
                        json.dump(observation, stream, sort_keys=True)
                        stream.write('\n')
                        stream.flush()
                        os.replace(temporary, Path(os.environ['RUNNER_TEMP']) / 'publication-fetch-source.json')
                    finally:
                        temporary.unlink(missing_ok=True)
            except OSError:
                print('Could not retain publication source diagnostics.', file=sys.stderr)


def fetch(observation):
    cfg = config(Path('ci/decision-policy.json'), live=True)
    run_id, attempt = int(os.environ['QUALIFICATION_RUN']), int(os.environ['QUALIFICATION_ATTEMPT'])
    started = time.monotonic_ns()
    found = find_packets(cfg, run_id, attempt)
    observation['discoveryMilliseconds'] = (time.monotonic_ns() - started) // 1_000_000
    if not found:
        if os.environ.get('XO_NIXPKG_PUBLICATION_METADATA_ONLY') == 'true':
            observation['status'] = 'no-exact-packet'
            raise SystemExit(4)
        raise ValueError('no retained immutable decision packet for the requested qualification run and attempt')
    output = Path(os.environ['XO_NIXPKG_EVIDENCE'])
    if os.environ.get('XO_NIXPKG_PUBLICATION_METADATA_ONLY') == 'true':
        if len(found) != 1:
            observation['status'] = 'ambiguous-exact-packets'
            raise ValueError('Ambiguous exact-run publication packets')
        packet = found[0]
        started = time.monotonic_ns()
        values = {name: packets.metadata_bytes(packet['reference'], packet['sha256'], name, producer=packet['producer'])
                  for name in ('product.json', 'scans.json')}
        output.mkdir()
        import json
        for name, value in values.items():
            (output/name).write_bytes(value)
        output.with_suffix('.source.json').write_text(json.dumps(packet))
        observation.update(status='exact-packet', metadataMilliseconds=(time.monotonic_ns() - started) // 1_000_000)
        return
    if os.environ.get('XO_NIXPKG_RESCAN_INVENTORY_ONLY') == 'true':
        if len(found) != 1:
            raise ValueError('Ambiguous exact-run inventory packets')
        inventory_only(found[0], output)
        return
    # Caller owns short-lived registry login; this helper reads data only.
    packet = found[0]
    manifest = packets.fetch(packet['reference'], output, packet['sha256'])
    if manifest['producer'] != packet['producer']:
        raise ValueError('retained candidate producer differs from immutable descriptor')
    (output / 'decision-packet.json').unlink()


if __name__ == '__main__':
    main()
