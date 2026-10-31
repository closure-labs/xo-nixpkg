# SPDX-License-Identifier: Apache-2.0
"""Small versioned stage summaries without credentials, argv or API bodies."""
import json
import os
from pathlib import Path
import time


def stage(name, started, *, cache=None, transferred_bytes=0, freshness=None, queue=None, remote=None, checkpoints=None):
    allowed = {'inventory-generation', 'packet-materialization', 'qualification-inspection', 'destination-verification', 'queue-reconciliation'}
    if (name not in allowed or cache not in (None, 'hit', 'miss')
            or type(transferred_bytes) is not int or transferred_bytes < 0
            or freshness not in (None, 'current', 'expired', 'unknown')
            or remote not in (None, 'missing', 'partial', 'verified', 'conflict', 'unavailable')
            or queue not in (None, 'waiting', 'queued', 'merged', 'closed', 'changed-head', 'awaiting-review', 'awaiting-checks')
            or checkpoints is not None and any(value not in ('cache', 'handoff', 'assets', 'tags', 'flakehub') for value in checkpoints)):
        raise ValueError('Invalid stage summary')
    value = {'schema': 1, 'stage': name, 'elapsedSeconds': round(time.monotonic() - started, 3),
             'cacheOutcome': cache, 'transferredBytes': transferred_bytes, 'freshness': freshness,
             'queueState': queue, 'remoteVerification': remote, 'checkpoints': checkpoints or []}
    if os.environ.get('RUNNER_TEMP'):
        with (Path(os.environ['RUNNER_TEMP']) / 'ci-stage-summary.jsonl').open('a') as stream:
            stream.write(json.dumps(value, sort_keys=True) + '\n')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as stream:
            stream.write(f'- {name}: {value["elapsedSeconds"]}s; cache {cache or "n/a"}; transferred {transferred_bytes} bytes; '
                         f'freshness {freshness or "n/a"}; remote {remote or "n/a"}.\n')
    return value


def authority_requests(count, status):
    """Count only calls through the authority API callback, not all HTTP traffic."""
    import stat
    if type(count) is not int or not 0 <= count <= 100000 or status not in ('passed', 'blocked'):
        raise ValueError('Invalid authority request-count observation')
    value = {'schema': 1, 'scope': 'publication-authority-callback',
             'calls': count, 'status': status, 'authorityClaim': False}
    if os.environ.get('RUNNER_TEMP'):
        path = Path(os.environ['RUNNER_TEMP']) / 'authority-api-requests.jsonl'
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError('Request-count diagnostic target is not a regular file')
            os.write(descriptor, (json.dumps(value, sort_keys=True) + '\n').encode())
        finally:
            os.close(descriptor)
    return value
