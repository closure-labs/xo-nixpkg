#!/usr/bin/env python3
"""Exercise the production packet push using native ORAS and local OCI layouts."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci/decisions'))
import decision_packets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oras', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not str(args.oras).startswith('/nix/store/') or not args.oras.is_file():
        raise ValueError('A pinned native ORAS executable is required')
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = args.output / 'evidence'
    evidence.mkdir()
    original_evidence = {'scannedAt': '2026-10-20T08:49:00+00:00',
                         'expiresAt': '2026-10-22T08:49:00+00:00'}
    (evidence / 'scan.json').write_text(json.dumps(original_evidence, sort_keys=True) + '\n')
    (evidence / 'distribution-cache.tar.part-000').write_bytes(b'complete immutable candidate NAR transport')
    producer = {'workflow': '.github/workflows/qualification.yml',
                'runId': 393777, 'runAttempt': 1, 'revision': 'a' * 40}
    calls, manifests = [], []
    environment = {'HOME': str(args.output / 'empty-home'), 'PATH': str(args.oras.parent)}
    def local_push(arguments, **kwargs):
        index = len(calls)
        reference = next(value for value in arguments if value.startswith(decision_packets.REGISTRY + ':'))
        # Only the destination and executable change; production annotations,
        # packet bytes, layer order, media types and exported manifest are used.
        argv = [str(args.oras), *arguments[1:]]
        argv[argv.index(reference)] = str(args.output / ('layout-' + str(index))) + ':' + reference.split(':')[-1]
        argv.insert(2, '--oci-layout')
        result = subprocess.run(argv, cwd=kwargs['cwd'], env=environment,
                                text=True, capture_output=True, check=True, timeout=60)
        manifest = Path(arguments[arguments.index('--export-manifest')+1]).read_bytes()
        (args.output / ('manifest-' + str(index) + '.json')).write_bytes(manifest)
        manifests.append(manifest)
        calls.append({'command': argv, 'wallClockSeconds': time.time(),
                      'stdout': result.stdout, 'stderr': result.stderr})
        return result.stdout.encode()
    with patch.object(decision_packets, 'command', side_effect=local_push), \
         patch.object(decision_packets, 'private_review_registry') as privacy:
        first = decision_packets.push(evidence, producer)
        time.sleep(1.2)
        second = decision_packets.push(evidence, producer)
        assert privacy.call_count == 4
    receipt = {'schema': 1, 'nativeOras': str(args.oras),
               'sourceSha256': hashlib.sha256((ROOT / 'ci/decisions/decision_packets.py').read_bytes()).hexdigest(),
               'networkOrCredentialsUsed': False, 'calls': calls, 'results': [first, second],
               'manifestDigests': [hashlib.sha256(value).hexdigest() for value in manifests],
               'manifestIdentical': manifests[0] == manifests[1],
               'elapsedBetweenPushesSeconds': calls[1]['wallClockSeconds'] - calls[0]['wallClockSeconds'],
               'producerUnchanged': first['producer'] == second['producer'] == producer,
               'scanEvidenceUnchanged': json.loads((evidence / 'scan.json').read_text()) == original_evidence,
               'temporaryPacketRemoved': not (evidence / 'decision-packet.json').exists()}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps(receipt, sort_keys=True, indent=2))
    assert receipt['elapsedBetweenPushesSeconds'] > 1
    assert receipt['manifestIdentical'] and first == second, 'Identical canonical packets changed OCI digest'
    assert receipt['producerUnchanged'] and receipt['scanEvidenceUnchanged'] and receipt['temporaryPacketRemoved']


if __name__ == '__main__':
    main()
