#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inspect retained exact-run observations before deciding to materialize payloads."""
import datetime as dt
import json
import os
from pathlib import Path
import sys
import common
import operations
import observability
import time
import tempfile
import decision_packets as packets
import scheduling
import importlib.util
spec = importlib.util.spec_from_file_location('fetch_retained', os.environ['XO_NIXPKG_RETAINED_FETCH_SOURCE'])
retained = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retained)
find_packets = retained.find_packets


def inspect_qualification():
    started = time.monotonic()
    cfg = common.config(Path('ci/decision-policy.json'), live=True)
    run_id, attempt = int(os.environ['QUALIFICATION_RUN']), int(os.environ['QUALIFICATION_ATTEMPT'])
    local = os.environ.get('XO_NIXPKG_INSPECT_LOCAL_EVIDENCE') == 'true'
    found = [None] if local else find_packets(cfg, run_id, attempt)
    if not found:
        # Successful discovery with no retained descriptor requires authenticated
        # Actions materialization; missing/unavailable evidence is not success.
        outcome = scheduling.result(cfg['repository'], os.environ['QUALIFICATION_SOURCE_SHA'],
            os.environ['GITHUB_SHA'], run_id, attempt, 'materialize', 'evidence-required')
        outcome.update(status='unretained', usableEvidence=False)
        common.emit(outcome)
        return
    observations = []
    for packet in found:
        with tempfile.TemporaryDirectory(prefix='xo-policy-inspection-') as temporary:
            directory = Path(os.environ['XO_NIXPKG_EVIDENCE']) if local else Path(temporary)
            if not local:
                for name in ('scans.json', 'product.json'):
                    data = packets.metadata_bytes(packet['reference'], packet['sha256'], name,
                                                  producer=packet['producer'])
                    (directory / name).write_bytes(data)
            native, expires, policy_state = scheduling.authenticated_policy_observation(directory, cfg)
        producer = native.get('producer', {})
        normalized = dict(producer, repository=cfg['repository'],
                          revision=producer.get('revision', native['revision']), sourceRevision=native['revision'])
        if (native.get('repository') != cfg['repository'] or producer.get('runId') != run_id
                or producer.get('runAttempt') != attempt
                or (packet is not None and normalized != packet['producer'])
                or normalized['revision'] != os.environ['QUALIFICATION_SOURCE_SHA']):
            raise ValueError('Retained observation differs from selected source and complete producer')
        observations.append((expires, native, packet, policy_state))
    # Distinct security/product packets may carry the exact same observations;
    # conflicting retained observations cannot silently suppress work.
    identities = {common.canonical_hash(native) for _, native, _, _ in observations}
    if len(identities) != 1:
        raise ValueError('Ambiguous retained observations for exact producer')
    expires, native, packet, policy_state = observations[0]
    if policy_state == 'awaiting-current-evidence':
        outcome = scheduling.result(cfg['repository'], native['revision'], os.environ['GITHUB_SHA'],
            run_id, attempt, 'wait', 'obsolete-policy')
        outcome.update(status='awaiting-current-evidence', usableEvidence=False)
        common.emit(outcome)
        return
    expired = dt.datetime.now(dt.timezone.utc) >= expires
    outcome = scheduling.result(cfg['repository'], native['revision'], os.environ['GITHUB_SHA'],
        run_id, attempt, 'refresh' if expired else 'inspect',
        'observations-expired' if expired else 'publication-observed',
        packet=None if packet is None else {'reference': packet['reference'], 'sha256': packet['sha256']})
    outcome.update(status='expired' if expired else 'current', expiresAt=expires.isoformat(), usableEvidence=False)
    observability.stage('qualification-inspection', started, freshness='expired' if expired else 'current')
    common.emit(outcome)


def main():
    with operations.budget(90):
        return inspect_qualification()


if __name__ == '__main__':
    sys.exit(common.run(main))
