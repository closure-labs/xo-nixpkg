#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh protected-main native posture/alert observation at EVERY publication boundary.

No audit-run or saved-receipt fallback. Product vulnerability/authority checks
remain in publication-gate.sh after this independent live prerequisite.
"""
import importlib.util
import base64
import hashlib
import re
import json
import os
from pathlib import Path
import subprocess
import sys

path = os.environ.get('XO_NATIVE_SECRET_CONTROLLER_SOURCE', str(Path(__file__).with_name('native-secret-controller.py')))
spec = importlib.util.spec_from_file_location('native_publication_observer', path)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def incoming_check(api, revision):
    """Use existing GitHub run/job metadata; no saved receipt or custom publisher."""
    workflow = '.github/workflows/repository-secret-scan.yml'
    listing = api.get(native.PREFIX + '/actions/workflows/repository-secret-scan.yml/runs?head_sha=' + revision + '&event=merge_group&per_page=100')
    native.require(isinstance(listing, dict) and type(listing.get('total_count')) is int
                   and 0 < listing['total_count'] < 100, 'incoming-run-inventory')
    rows = listing.get('workflow_runs')
    native.require(isinstance(rows, list) and len(rows) == listing['total_count'], 'incoming-run-inventory')
    native.require(all(type(r.get('id')) is int and r['id'] > 0 for r in rows), 'incoming-run-schema')
    latest_id = max(r['id'] for r in rows)
    run = api.get(native.PREFIX + '/actions/runs/' + str(latest_id))
    native.require(run.get('id') == latest_id and run.get('head_sha') == revision and run.get('event') == 'merge_group'
                   and run.get('path') == workflow and run.get('status') == 'completed'
                   and run.get('conclusion') == 'success' and type(run.get('run_attempt')) is int
                   and run['run_attempt'] > 0 and run.get('repository', {}).get('id') == native.REPO_ID
                   and run.get('head_repository', {}).get('id') == native.REPO_ID, 'incoming-run-binding')
    commit = api.get(native.PREFIX + '/git/commits/' + revision)
    parents = commit.get('parents')
    native.require(isinstance(parents, list) and len(parents) == 2, 'incoming-source-parents')
    base = native.sha(parents[0].get('sha'))
    native.require(re.fullmatch(r'gh-readonly-queue/main/pr-[1-9][0-9]*-' + base, run.get('head_branch', '')) is not None, 'incoming-range-binding')
    expected = native.incoming_sources()
    for path, ref, key in [(workflow, revision, 'workflowSha256'), ('.gitleaks.toml', base, 'configSha256')]:
        value = api.get(native.PREFIX + '/contents/' + path + '?ref=' + ref)
        native.require(value.get('encoding') == 'base64' and type(value.get('size')) is int
                       and value['size'] <= 65536, 'incoming-source-schema')
        try:
            data = base64.b64decode(''.join(value['content'].split()), validate=True)
        except Exception:
            raise native.Blocked('incoming-source-schema') from None
        native.require(len(data) == value['size'] and hashlib.sha256(data).hexdigest() == expected[key], 'incoming-policy-changed')
    jobs = api.get(native.PREFIX + '/actions/runs/' + str(run['id']) + '/attempts/' + str(run['run_attempt']) + '/jobs?per_page=100')
    native.require(type(jobs.get('total_count')) is int and jobs['total_count'] < 100
                   and len(jobs.get('jobs', [])) == jobs['total_count'], 'incoming-job-inventory')
    selected = [j for j in jobs['jobs'] if j.get('name') == 'Repository security audit']
    native.require(len(selected) == 1 and selected[0].get('status') == 'completed'
                   and selected[0].get('conclusion') == 'success' and selected[0].get('head_sha') == revision
                   and type(selected[0].get('id')) is int, 'incoming-job-binding')
    check = api.get(native.PREFIX + '/check-runs/' + str(selected[0]['id']))
    native.require(check.get('app', {}).get('id') == 15368 and check.get('head_sha') == revision
                   and check.get('name') == 'Repository security audit' and check.get('conclusion') == 'success', 'incoming-check-owner')
    return {'runId': run['id'], 'runAttempt': run['run_attempt'], 'base': base, 'head': revision}


def verify(controller, product, scans, api, now=None, metadata_api=None):
    native.sha(controller)
    native.require(isinstance(product, dict) and product.get('repository') == native.REPO, 'product-schema')
    revision = native.sha(product.get('revision'))
    native.validate_product_policy(product, scans)
    proof = incoming_check(metadata_api or api, revision)
    receipt = native.observe(api, controller, {'sha': revision, 'kind': 'product', 'run': None},
                             metadata_api=metadata_api, **({'now': now} if now is not None else {}))
    # Native collection can overlap a rerun or a newer queue run. Re-read the
    # latest run, its current attempt and actual job/check after collection.
    native.require(incoming_check(metadata_api or api, revision) == proof, 'incoming-scan-changed')
    receipt['incomingScan'] = proof
    return receipt



EVIDENCE_LIMITS = {'product.json': 16 * 1024**2, 'scans.json': 128 * 1024**2}
SAFE_FAILURE_CODES = frozenset({
    'evidence-file', 'json-schema', 'duplicate-json-key',
    'observer-token-unavailable', 'alerts-permission-unavailable',
    'alerts-unavailable', 'protected-main-moved',
})


def read_evidence(directory, name):
    native.require(name in EVIDENCE_LIMITS, 'evidence-file')
    path = directory / name
    native.require(path.is_file() and not path.is_symlink()
                   and path.stat().st_size <= EVIDENCE_LIMITS[name], 'evidence-file')
    return native.decode(path.read_bytes())


def failure_message(error):
    # Only fixed guard codes may reach logs; never expose arbitrary API errors,
    # response bodies, report content, paths or credential-bearing exceptions.
    code = str(error) if isinstance(error, native.Blocked) else ''
    if code not in SAFE_FAILURE_CODES:
        code = 'validation-failed'
    return 'Publication blocked: security prerequisite failed (' + code + ')'


def main():
    native.require(os.environ.get('GITHUB_REPOSITORY') == native.REPO
                   and os.environ.get('GITHUB_REF') == 'refs/heads/main', 'controller-context')
    controller = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    directory = Path(os.environ['XO_NIXPKG_EVIDENCE'])
    values = []
    for name in ('product.json', 'scans.json'):
        values.append(read_evidence(directory, name))
    receipt = verify(controller, *values, native.API(os.environ.get('NATIVE_SECRET_OBSERVER_TOKEN')),
                     metadata_api=native.MetadataAPI(os.environ.get('GH_TOKEN')))
    print(json.dumps({'status': 'observed', 'policyId': receipt['policyId'],
                      'fullHistoryCompletionClaim': False, 'openAlertCount': 0, 'incomingScan': receipt['incomingScan']}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(failure_message(error), file=sys.stderr)
        raise SystemExit(1)
