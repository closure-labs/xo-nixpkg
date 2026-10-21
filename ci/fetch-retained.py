#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Recover exact candidate bytes from private, digest-bound reviewed evidence."""
import os
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


def main():
    cfg = config(Path('ci/decision-policy.json'), live=True)
    run_id, attempt = int(os.environ['QUALIFICATION_RUN']), int(os.environ['QUALIFICATION_ATTEMPT'])
    found = find_packets(cfg, run_id, attempt)
    if not found:
        if os.environ.get('XO_NIXPKG_PUBLICATION_METADATA_ONLY') == 'true':
            raise SystemExit(4)
        raise ValueError('candidate artifact expired without a retained immutable decision packet')
    output = Path(os.environ['XO_NIXPKG_EVIDENCE'])
    if os.environ.get('XO_NIXPKG_PUBLICATION_METADATA_ONLY') == 'true':
        if len(found) != 1:
            raise ValueError('Ambiguous exact-run publication packets')
        packet = found[0]
        values = {name: packets.metadata_bytes(packet['reference'], packet['sha256'], name, producer=packet['producer'])
                  for name in ('product.json', 'scans.json')}
        output.mkdir()
        import json
        for name, value in values.items():
            (output/name).write_bytes(value)
        output.with_suffix('.source.json').write_text(json.dumps(packet))
        return
    # Caller owns short-lived registry login; this helper reads data only.
    packet = found[0]
    manifest = packets.fetch(packet['reference'], output, packet['sha256'])
    if manifest['producer'] != packet['producer']:
        raise ValueError('retained candidate producer differs from immutable descriptor')
    (output / 'decision-packet.json').unlink()


if __name__ == '__main__':
    main()
