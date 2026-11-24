#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Open a native release-review PR containing only one exact publication request."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).with_name('decisions')))
import common
import native_approvals as native
import decision_packets as packets


def api(endpoint, body=None, method=None, missing=False):
    args = ['gh', 'api', '--method', method or ('POST' if body is not None else 'GET'), endpoint]
    if body is not None:
        args += ['--input', '-']
    result = subprocess.run(args, input=None if body is None else json.dumps(body),
                            text=True, capture_output=True, timeout=60)
    if result.returncode:
        if missing and re.search(r'HTTP 404\b', result.stderr):
            return None
        raise ValueError('Native release PR API operation failed')
    return json.loads(result.stdout) if result.stdout.strip() else None


def document(call, prefix, path, revision):
    value = call(prefix + '/contents/' + path + '?ref=' + revision, missing=True)
    if value is None:
        return None
    common.require(value.get('type') == 'file' and value.get('target') is None
                   and type(value.get('size')) is int and 0 < value['size'] <= 65536,
                   'Release request path must remain one bounded regular Git blob')
    return packets.decode_json(native.github.decode_blob(value, value.get('sha'), value.get('size')))


def propose(cfg, request, review_run, call=api):
    native.validate_request(cfg, request)
    common.require(type(review_run) is int and review_run > 0, 'Immutable review evidence run required')
    prefix = 'repos/' + cfg['repository']
    base = call(prefix + '/git/ref/heads/main')['object']['sha']
    common.require(isinstance(base, str) and common.SHA.fullmatch(base), 'Invalid protected-main base')
    if document(call, prefix, cfg['releaseRequestPath'], base) == request:
        return {'status': 'already-approved', 'head': base}
    # The trusted generator uses one file. GitHub owns reviews, stale dismissal,
    # CODEOWNERS, queue admission and merge, including concurrent proposals.
    branch = 'automation/release-' + request['purpose']
    ref = call(prefix + '/git/ref/heads/' + branch, missing=True)
    old = ref['object']['sha'] if ref is not None else None
    common.require(old is None or isinstance(old, str) and common.SHA.fullmatch(old), 'Invalid release branch')
    pulls = call(prefix + '/pulls?state=open&base=main&head=closure-labs:' + branch)
    common.require(isinstance(pulls, list) and len(pulls) <= 1, 'Ambiguous release PR inventory')
    common.require(not pulls or pulls[0].get('user', {}).get('login') == 'cl-decider[bot]',
                   'Release proposal must retain its automation author')
    head = old
    if old is None or document(call, prefix, cfg['releaseRequestPath'], old) != request:
        commit = call(prefix + '/git/commits/' + base)
        tree = call(prefix + '/git/trees', {'base_tree': commit['tree']['sha'], 'tree': [{
            'path': cfg['releaseRequestPath'], 'mode': '100644', 'type': 'blob',
            'content': json.dumps(request, sort_keys=True, indent=2, allow_nan=False) + '\n'}]})
        parents = list(dict.fromkeys([value for value in (old, base) if value is not None]))
        created = call(prefix + '/git/commits', {'message': 'Request native review of qualified ' + request['purpose'] + ' product',
                                              'tree': tree['sha'], 'parents': parents})
        head = created['sha']
        common.require(isinstance(head, str) and common.SHA.fullmatch(head), 'Invalid release proposal commit')
        if old is None:
            call(prefix + '/git/refs', {'ref': 'refs/heads/' + branch, 'sha': head})
        else:
            call(prefix + '/git/refs/heads/' + branch, {'sha': head, 'force': False}, method='PATCH')
    observed = call(prefix + '/git/ref/heads/' + branch)
    common.require(observed.get('object', {}).get('sha') == head, 'Release branch moved during proposal')
    body = ('Approve publication of the exact qualified product and findings below by reviewing this PR. '
            'Merging this single request through native GitHub rules triggers publication; no comment commands or environment review are required.\n\n'
            '| Binding | Value |\n| --- | --- |\n')
    for key in ('purpose', 'sourceRevision', 'qualificationRun', 'qualificationAttempt', 'productHash', 'scansHash', 'policyHash'):
        body += '| ' + key + ' | `' + str(request[key]) + '` |\n'
    body += '\n| Profile | Findings |\n| --- | --- |\n'
    for name, count in request['findingCounts'].items():
        body += '| ' + name + ' | ' + str(count) + ' |\n'
    body += ('\n[Complete findings and authenticated review artifacts](https://github.com/' + cfg['repository']
             + '/actions/runs/' + str(review_run) + ') (`publication-review`). '
             'Scan freshness and exact hashes are revalidated before every publishing boundary. '
             'Changed evidence needs an updated request and a new native review.\n')
    title = 'release: review qualified ' + request['purpose'] + ' product'
    if pulls:
        pull = pulls[0]
        common.require(pull.get('user', {}).get('login') == 'cl-decider[bot]', 'Release proposal must retain its automation author')
        pull = call(prefix + '/pulls/' + str(pull['number']), {'title': title, 'body': body}, method='PATCH')
    else:
        pull = call(prefix + '/pulls', {'head': branch, 'base': 'main', 'title': title, 'body': body, 'draft': False})
    common.require(pull.get('user', {}).get('login') == 'cl-decider[bot]', 'Unexpected native release proposal author')
    return {'number': pull['number'], 'head': head, 'url': pull['html_url']}


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--request', required=True, type=Path)
    args = cli.parse_args()
    cfg = native.policy(live=True)
    common.require(os.environ.get('GITHUB_REPOSITORY') == cfg['repository']
                   and os.environ.get('GITHUB_REF') == 'refs/heads/main', 'Release proposals require protected main')
    request = native.read_request(cfg, args.request)
    # Resolve and validate the complete request before any branch or PR write.
    result = propose(cfg, request, int(os.environ['GITHUB_RUN_ID']))
    if result.get('status') == 'already-approved':
        common.emit(result)
        return
    subprocess.run(['gh', 'pr', 'merge', str(result['number']), '--repo', cfg['repository'], '--auto', '--merge',
                    '--match-head-commit', result['head']], check=True, capture_output=True, timeout=60)
    common.emit(result)


if __name__ == '__main__':
    sys.exit(common.run(main))
