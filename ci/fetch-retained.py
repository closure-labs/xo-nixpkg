#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Recover exact candidate bytes from authenticated Actions or immutable handoff evidence."""
import json
import os
import sys
import time
import tempfile
from pathlib import Path
import re
import subprocess

import decision_authority as authority
import decision_packets as packets
from native_approvals import policy as config
import publication_receipts


def optional_metadata(endpoint):
    result = subprocess.run(['gh', 'api', '--method', 'GET', endpoint], text=True,
                            capture_output=True, timeout=30)
    if result.returncode and re.search(r'HTTP 404\b', result.stderr):
        return None
    if result.returncode:
        raise ValueError('Publication transport metadata is unavailable')
    return packets.decode_json(result.stdout)


def published_packet(cfg, run_id, attempt):
    """An exact completed public handoff can supply retry bytes, never approval."""
    if 'releaseRequestPath' not in cfg:
        return None
    prefix = 'repos/' + cfg['repository']
    revision = authority.github_api(prefix + '/git/ref/heads/main')['object']['sha']
    metadata = optional_metadata(prefix + '/contents/' + cfg['releaseRequestPath'] + '?ref=' + revision)
    if metadata is None:
        return None
    from native_approvals import validate_request
    request = validate_request(cfg, packets.decode_json(authority.decode_blob(metadata, metadata.get('sha'), metadata.get('size'))))
    if (request['qualificationRun'], request['qualificationAttempt']) != (run_id, attempt):
        return None
    ref = optional_metadata(prefix + '/git/ref/heads/automation/publication-' + request['productHash'])
    if ref is None:
        return None
    commit = ref.get('object', {}).get('sha')
    if ref.get('object', {}).get('type') != 'commit' or not isinstance(commit, str) or not authority.SHA.fullmatch(commit):
        raise ValueError('Publication journal reference has an invalid identity')
    journal = authority.document_at(authority.github_api, cfg['repository'], 'journal.json', commit)
    receipts = publication_receipts.read(journal, request['productHash'])
    if 'handoff' not in receipts:
        return None
    packet = receipts['handoff']['expected']
    producer = packet.get('producer', {})
    if not any(step.get('name') == 'handoff' and step.get('state') == 'complete'
               and step.get('identity') == packet for step in journal.get('steps', [])):
        raise ValueError('Public handoff has no completed exact journal step')
    if (producer.get('repository') != cfg['repository'] or producer.get('runId') != run_id
            or producer.get('runAttempt') != attempt):
        return None
    registry = 'ghcr.io/' + cfg['repository'].lower() + '-products'
    if (not isinstance(packet.get('reference'), str)
            or not re.fullmatch(re.escape(registry) + r'@sha256:[a-f0-9]{64}', packet['reference'])
            or not isinstance(packet.get('sha256'), str) or not re.fullmatch(r'[a-f0-9]{64}', packet['sha256'])):
        raise ValueError('Public handoff transport reference differs')
    packets.REGISTRY, packets.REFERENCE = registry, re.compile(re.escape(registry) + r'@sha256:[a-f0-9]{64}')
    return packet


def find_packets(cfg, run_id, attempt):
    """Compatibility discovery for historical transport, never approval.

    New release requests use native Actions artifacts. Old immutable OCI packets
    remain readable for restoring pre-migration products; graph shape, decision
    disposition and prior reviews have no role in native release admission.
    """
    from common import ledger
    if any(type(value) is not int or value <= 0 for value in (run_id, attempt)):
        raise ValueError('Exact qualification run and attempt required')
    published = published_packet(cfg, run_id, attempt)
    if published is not None:
        return [published]
    if cfg.get('approvalMode') == 'github-pr-v1' and os.environ.get('XO_NIXPKG_PUBLICATION_METADATA_ONLY') == 'true':
        # A first native publication uses its fresh Actions artifact. Historical
        # decisions must not become a dependency of the new approval path.
        return []
    _, records = ledger(cfg)
    found = {}
    for document in records.values():
        packet = document.get('payload', {}).get('packet', {})
        producer = packet.get('producer', {})
        if (producer.get('repository') == cfg['repository'] and producer.get('runId') == run_id
                and producer.get('runAttempt') == attempt):
            reference, digest = packet.get('reference'), packet.get('sha256')
            if (not isinstance(reference, str) or not packets.REFERENCE.fullmatch(reference)
                    or not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest)):
                raise ValueError('Unsafe historical transport reference')
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
    cfg = config(live=True)
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
