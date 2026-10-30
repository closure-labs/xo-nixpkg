#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Protected-main native observation. No candidate checkout or alert payload output."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

spec = importlib.util.spec_from_file_location('native_contract', os.environ.get('XO_NATIVE_SECRET_CONTRACT_SOURCE', str(Path(__file__).with_name('native-secret-observation.py'))))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
Blocked = contract.Blocked
require = contract.require
REPO = contract.REPOSITORY
REPO_ID = 1198726032
PREFIX = '/repos/' + REPO
MAX_BODY = 2 * 1024 * 1024
CHECK = 'Repository security audit'


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Blocked('json-schema')))
    except (ValueError, UnicodeError):
        raise Blocked('json-schema') from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Blocked('redirect-rejected')


@contextmanager
def wall_budget(seconds):
    """Interrupt even a slow-drip HTTP read at the aggregate deadline."""
    def expired(_signal, _frame):
        raise Blocked('collection-expired')
    previous = signal.signal(signal.SIGALRM, expired)
    old_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    began = time.monotonic()
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if old_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, max(0.000001, old_timer[0] - (time.monotonic() - began)), old_timer[1])


class API:
    def __init__(self, token, monotonic=time.monotonic):
        require(isinstance(token, str) and bool(token), 'observer-token-unavailable')
        self.token, self.clock = token, monotonic
        self.deadline = monotonic() + 120
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, path, method='GET', body=None):
        require(isinstance(path, str) and (path == PREFIX or path.startswith(PREFIX + '/'))
                and not any(c in path for c in ('\r', '\n', '#', '\\')), 'request-scope')
        remaining = self.deadline - self.clock()
        require(remaining > 0, 'collection-expired')
        request = urllib.request.Request('https://api.github.com' + path,
            data=None if body is None else contract.canonical(body), method=method,
            headers={'Authorization': 'Bearer ' + self.token, 'User-Agent': 'xo-native-secret-observation',
                     'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
                     'Content-Type': 'application/json', 'Cache-Control': 'no-cache'})
        try:
            with wall_budget(remaining), self.opener.open(request, timeout=min(15, remaining)) as response:
                require(response.geturl() == request.full_url, 'redirect-rejected')
                raw = response.read(MAX_BODY + 1)
                require(len(raw) <= MAX_BODY, 'response-size')
                require(self.clock() <= self.deadline, 'collection-expired')
                return response.status, dict(response.headers), decode(raw)
        except urllib.error.HTTPError as error:
            # Never read or echo arbitrary error bodies (which may contain secrets).
            error.close()
            if '/secret-scanning/alerts?' in path and error.code == 403:
                raise Blocked('alerts-permission-unavailable') from None
            if '/secret-scanning/alerts?' in path and error.code == 404:
                raise Blocked('alerts-unavailable') from None
            code = error.code if type(error.code) is int and 100 <= error.code <= 599 else 0
            raise Blocked('api-http-' + str(code)) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise Blocked('api-network') from None

    def get(self, path):
        status, _, value = self.request(path)
        require(status == 200, 'api-status')
        return value


class MetadataAPI(API):
    def request(self, path, method='GET', body=None):
        require(method == 'GET' and '/secret-scanning/' not in path, 'metadata-read-only')
        return super().request(path, method, body)


def sha(value):
    require(isinstance(value, str) and contract.SHA.fullmatch(value), 'head-schema')
    return value


def current_main(api, controller):
    value = api.get(PREFIX + '/git/ref/heads/main')
    require(isinstance(value, dict) and value.get('ref') == 'refs/heads/main'
            and value.get('object', {}).get('type') == 'commit'
            and value['object'].get('sha') == controller, 'protected-main-moved')
    return controller


def next_page(headers, expected):
    link = next((v for k, v in headers.items() if k.lower() == 'link'), '')
    require(isinstance(link, str) and len(link) <= 8192, 'pagination-schema')
    if not link:
        return False
    found, relations = False, set()
    for piece in link.split(','):
        match = re.fullmatch(r'\s*<([^<>]+)>;\s*rel="(next|prev|first|last)"\s*', piece)
        require(match is not None and match[2] not in relations, 'pagination-schema')
        relations.add(match[2])
        parsed = urllib.parse.urlsplit(match[1])
        require(parsed.scheme == 'https' and parsed.netloc == 'api.github.com'
                and not parsed.fragment and parsed.path == PREFIX + '/secret-scanning/alerts', 'pagination-origin')
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        require(set(query) == {'state', 'hide_secret', 'per_page', 'page'}
                and query['state'] == ['open'] and query['hide_secret'] == ['true']
                and query['per_page'] == ['100'] and len(query['page']) == 1
                and re.fullmatch(r'[1-9][0-9]{0,5}', query['page'][0]), 'pagination-scope')
        if match[2] == 'next':
            require(int(query['page'][0]) == expected, 'pagination-cycle')
            found = True
    return found


def alert_pass(api):
    pages = []
    for number in range(1, contract.POLICY['maxAlertPagesPerPass'] + 1):
        path = PREFIX + f'/secret-scanning/alerts?state=open&hide_secret=true&per_page=100&page={number}'
        status, headers, rows = api.request(path)
        more = next_page(headers, number + 1)
        pages.append({'origin': 'https://api.github.com', 'requestPath': path,
                      'httpStatus': status, 'hideSecret': True, 'hasNext': more, 'alerts': rows})
        if not more:
            contract.inventory(pages)
            return pages
    raise Blocked('pagination-bound')


def target(api, run_id, controller):
    current_main(api, controller)
    if run_id is None:
        return {'sha': controller, 'kind': 'main', 'run': None}
    require(type(run_id) is int and run_id > 0, 'event-run-id')
    run = api.get(PREFIX + '/actions/runs/' + str(run_id))
    require(isinstance(run, dict) and run.get('id') == run_id
            and run.get('repository', {}).get('full_name') == REPO
            and run['repository'].get('id') == REPO_ID
            and run.get('head_repository', {}).get('id') == REPO_ID
            and run['head_repository'].get('full_name') == REPO
            and run.get('path') == '.github/workflows/ci.yml'
            and run.get('status') == 'completed'
            and run.get('conclusion') == 'success'
            and run.get('event') in ('pull_request', 'merge_group'), 'event-run-binding')
    head = sha(run.get('head_sha'))
    branch = run.get('head_branch')
    if run['event'] == 'merge_group':
        require(isinstance(branch, str) and re.fullmatch(r'gh-readonly-queue/main/pr-[1-9][0-9]*-[a-f0-9]{7,40}', branch), 'queue-ref')
        ref = api.get(PREFIX + '/git/ref/heads/' + branch)
        require(ref.get('object', {}).get('sha') == head, 'queue-head-race')
        return {'sha': head, 'kind': 'merge_group', 'run': run_id, 'branch': branch}
    candidates = api.get(PREFIX + '/commits/' + head + '/pulls?per_page=100')
    require(isinstance(candidates, list) and len(candidates) < 100, 'pull-inventory')
    matches = []
    for candidate in candidates:
        number = candidate.get('number') if isinstance(candidate, dict) else None
        require(type(number) is int and number > 0, 'pull-schema')
        pull = api.get(PREFIX + '/pulls/' + str(number))
        if pull.get('state') != 'open' or pull.get('head', {}).get('sha') != head:
            continue
        require(pull.get('base', {}).get('ref') == 'main'
                and pull['base'].get('repo', {}).get('id') == REPO_ID
                and pull['base']['repo'].get('full_name') == REPO
                and pull.get('head', {}).get('repo', {}).get('id') == REPO_ID
                and pull['head']['repo'].get('full_name') == REPO
                and pull['head'].get('ref') == branch, 'foreign-pull')
        matches.append(number)
    require(len(matches) == 1, 'pull-head-unavailable-or-ambiguous')
    return {'sha': head, 'kind': 'pull_request', 'run': run_id, 'pull': matches[0]}


def observe(api, controller, selected, now=lambda: datetime.now(timezone.utc), metadata_api=None):
    metadata = metadata_api or api
    def binding():
        current_main(metadata, controller)
        if selected['kind'] == 'product':
            comparison = metadata.get(PREFIX + '/compare/' + selected['sha'] + '...' + controller)
            require(comparison.get('status') in ('ahead', 'identical')
                    and comparison.get('merge_base_commit', {}).get('sha') == selected['sha'], 'product-ancestry')
            return selected
        return target(metadata, selected['run'], controller)
    start = now().strftime('%Y-%m-%dT%H:%M:%SZ')
    require(binding() == selected, 'target-race')
    before = api.get(PREFIX)
    first, second = alert_pass(api), alert_pass(api)
    after = api.get(PREFIX)
    require(binding() == selected, 'target-race')
    end = now().strftime('%Y-%m-%dT%H:%M:%SZ')
    return contract.propose_receipt(policy=contract.POLICY, repository=REPO,
        candidate_before=selected['sha'], candidate_after=selected['sha'],
        main_before=controller, main_after=controller, posture_before=before, posture_after=after,
        passes=[first, second], started_at=start, completed_at=end, now=now())


def policy_binding():
    path = Path(os.environ.get('XO_NATIVE_SECRET_POLICY_PATH', str(Path(__file__).with_name('native-secret-policy.json'))))
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16384, 'policy-file')
    require(contract.canonical(decode(path.read_bytes())) == contract.canonical(contract.POLICY), 'policy-changed')
    return {'policyId': contract.POLICY_ID,
            'policySha256': __import__('hashlib').sha256(contract.canonical(contract.POLICY)).hexdigest()}


def validate_product_policy(product, scans):
    require(product.get('repositorySecretPolicy') == policy_binding()
            and scans.get('repositorySecretPolicy') == policy_binding(), 'old-policy-qualification')


def publish_check(api, selected, success, reason='native-observation-blocked', *, mode='bootstrap'):
    require(reason in ('observed', 'observer-token-unavailable', 'native-observation-blocked'), 'check-reason')
    require(mode in ('bootstrap', 'production'), 'observer-mode')
    require(mode != 'production' or contract.POLICY['activation'] == 'protected-main', 'policy-not-active')
    # Only the separately reviewed protected-main workflow selects production.
    # Bootstrap never infers authority from a policy document on disk.
    name = CHECK if mode == 'production' else 'Native secret observation (bootstrap)'
    body = {'name': name, 'head_sha': selected['sha'], 'status': 'completed',
            'conclusion': 'success' if success else 'failure',
            'output': {'title': name, 'summary': reason + '; posture/alert observation only; not full-history or exact-commit completion.'}}
    status, _, result = api.request(PREFIX + '/check-runs', 'POST', body)
    require(status == 201 and result.get('app', {}).get('id') == 15368, 'check-owner')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['scope', 'collect', 'check', 'qualification'])
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--run-id', type=int)
    parser.add_argument('--observer-mode', choices=['bootstrap', 'production'], default='bootstrap')
    args = parser.parse_args()
    require(os.environ.get('GITHUB_REPOSITORY') == REPO and os.environ.get('GITHUB_REF') == 'refs/heads/main', 'controller-context')
    controller = sha(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip())
    policy_binding()
    # A publication observer token is distinct from check/signer credentials.
    api = API(os.environ.get('GH_TOKEN') if args.operation in ('scope', 'check') else os.environ.get('NATIVE_SECRET_OBSERVER_TOKEN'))
    metadata = MetadataAPI(os.environ.get('GH_TOKEN') if args.operation in ('scope', 'check') else os.environ.get('REPOSITORY_READ_TOKEN'))
    selected = target(metadata, args.run_id, controller)
    if args.operation == 'scope':
        print(json.dumps({'status': 'bound', 'target': selected['sha'], 'kind': selected['kind']}))
        return
    if args.operation == 'check':
        receipt = decode(args.output.read_bytes()) if args.output.exists() else None
        success = (isinstance(receipt, dict) and receipt.get('status') == 'observed'
                   and receipt.get('candidateSha') == selected['sha']
                   and receipt.get('protectedMainSha') == controller
                   and receipt.get('policySha256') == policy_binding()['policySha256']
                   and contract.stamp(receipt['expiresAt']) >= datetime.now(timezone.utc))
        publish_check(api, selected, success, 'observed' if success else 'observer-token-unavailable', mode=args.observer_mode)
        return
    args.output.unlink(missing_ok=True)
    receipt = observe(api, controller, selected, metadata_api=metadata)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(contract.canonical(receipt) + b'\n')
    print(json.dumps({'status': 'observed', 'openAlertCount': 0, 'policyId': contract.POLICY_ID}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Fixed category, never str(error) from network/API/alert payloads.
        reason = str(error) if isinstance(error, Blocked) else 'native-observation-error'
        print(json.dumps({'status': 'blocked', 'reason': reason}), file=sys.stderr)
        raise SystemExit(1)
