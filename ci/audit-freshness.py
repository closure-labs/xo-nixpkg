#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail closed on publication unless current protected main has a fresh full audit.

This trusts the authenticated, exact-current-main workflow execution, never a
candidate-supplied receipt. A newer pending/failed attempt supersedes old success.
"""
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).with_name('decisions')))
import operations

REPOSITORY = 'closure-labs/xo-nixpkg'
WORKFLOW = '.github/workflows/security-audit.yml'
STEP = 'Full history audit contract v2'
MAX_AGE = dt.timedelta(hours=24)
SHA = re.compile(r'[a-f0-9]{40}')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def timestamp(value):
    require(isinstance(value, str), 'Missing audit timestamp')
    result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None, 'Audit timestamp lacks timezone')
    return result


def api(endpoint):
    result = operations.run(['gh', 'api', 'repos/' + REPOSITORY + '/' + endpoint],
                            capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, 'Full audit GitHub evidence unavailable')
    require(len(result.stdout) <= 4 * 1024 * 1024, 'Audit response exceeds bound')
    return json.loads(result.stdout)


def verify(controller, product, query=api, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    require(isinstance(controller, str) and SHA.fullmatch(controller), 'Invalid controller revision')
    require(isinstance(product, dict) and product.get('repository') == REPOSITORY
            and isinstance(product.get('revision'), str) and SHA.fullmatch(product['revision']),
            'Invalid publication source')
    def main():
        value = query('git/ref/heads/main')
        require(value.get('ref') == 'refs/heads/main' and value.get('object', {}).get('type') == 'commit',
                'Invalid protected main reference')
        return value['object'].get('sha')
    require(main() == controller, 'Publication controller is not current protected main')
    listing = query('actions/workflows/security-audit.yml/runs?head_sha=' + controller + '&per_page=1')
    runs = listing.get('workflow_runs')
    require(isinstance(runs, list) and len(runs) == 1, 'No current-policy complete history audit')
    run = runs[0]
    run_id, attempt = run.get('id'), run.get('run_attempt')
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
            'Invalid full audit run identity')
    def identity(value):
        require(value.get('id') == run_id and value.get('run_attempt') == attempt
                and value.get('head_sha') == controller and value.get('head_branch') == 'main'
                and value.get('path') == WORKFLOW and value.get('event') in ('push', 'schedule', 'workflow_dispatch')
                and value.get('repository', {}).get('full_name') == REPOSITORY
                and value.get('head_repository', {}).get('full_name') == REPOSITORY
                and value.get('status') == 'completed' and value.get('conclusion') == 'success',
                'Latest full history audit is untrusted, pending, or unsuccessful')
        start, end = timestamp(value.get('run_started_at')), timestamp(value.get('updated_at'))
        require(start <= end <= now and dt.timedelta(0) <= now - start < MAX_AGE,
                'Full history audit is stale or future-dated')
    identity(run)
    identity(query('actions/runs/' + str(run_id)))
    jobs = query(f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')
    require(type(jobs.get('total_count')) is int and jobs['total_count'] <= 100
            and len(jobs.get('jobs', [])) == jobs['total_count'], 'Incomplete full audit jobs')
    audit = [job for job in jobs['jobs'] if job.get('name') == 'Repository security audit']
    require(len(audit) == 1 and audit[0].get('head_sha') == controller
            and audit[0].get('run_id') == run_id
            and audit[0].get('status') == 'completed' and audit[0].get('conclusion') == 'success',
            'Missing successful exhaustive audit job')
    steps = [step for step in audit[0].get('steps', []) if step.get('name') == STEP]
    require(len(steps) == 1 and steps[0].get('status') == 'completed'
            and steps[0].get('conclusion') == 'success', 'Missing full history policy contract')
    if product['revision'] != controller:
        comparison = query('compare/' + product['revision'] + '...' + controller)
        require(comparison.get('status') in ('ahead', 'identical')
                and comparison.get('merge_base_commit', {}).get('sha') == product['revision'],
                'Publication source is outside audited protected history')
    require(main() == controller, 'Protected main changed during full audit validation')
    latest = query('actions/workflows/security-audit.yml/runs?head_sha=' + controller + '&per_page=1')
    require(isinstance(latest.get('workflow_runs'), list) and len(latest['workflow_runs']) == 1,
            'Full audit run changed during validation')
    identity(latest['workflow_runs'][0])
    return {'schema': 2, 'status': 'success', 'auditRun': run_id, 'auditAttempt': attempt,
            'auditedMain': controller, 'sourceRevision': product['revision'], 'maxAgeHours': 24}


def main():
    with operations.budget(120):
        controller = operations.run(['git', 'rev-parse', '--verify', 'HEAD'], capture_output=True,
                                    text=True, check=True, timeout=15).stdout.strip()
        path = Path(os.environ['XO_NIXPKG_EVIDENCE']) / 'product.json'
        require(path.is_file() and path.stat().st_size <= 1024 * 1024, 'Invalid product metadata size')
        print(json.dumps(verify(controller, json.loads(path.read_text())), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        print('Publication blocked: fresh current-policy full history audit required', file=sys.stderr)
        sys.exit(1)
