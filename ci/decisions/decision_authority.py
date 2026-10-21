#!/usr/bin/env python3
"""Authenticate human decisions against authoritative GitHub PR reviews, not ledger claims."""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote

from security_decisions import TechnicalError, canonical_hash, load_json

SHA = re.compile(r'[0-9a-f]{40}')
REPOSITORY = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
APPROVER_ORG = 'closure-labs'
APPROVER_TEAM = 'super-admins'
APPROVER_TEAM_ID = 20196962
# Complete four-profile ledgers exceed 8 MiB; keep an explicit immutable-blob cap.
MAX_PROPOSAL_BYTES = 16 * 1024**2
MAX_API_BYTES = 24 * 1024**2
KINDS = {'security-findings': 'security', 'security-revocation': 'security', 'release-set': 'releases', 'release-product': 'releases'}


class AuthorityError(ValueError):
    """No authenticated, currently valid human authority for the proposed operation."""


class HumanDecisionRequired(AuthorityError):
    """GitHub is reachable, but current human authorization is absent or withdrawn."""


def proposal_path(proposal):
    if (not isinstance(proposal, dict) or set(proposal) != {'schema', 'kind', 'payload'}
            or type(proposal['schema']) is not int or proposal['schema'] != 1 or proposal['kind'] not in KINDS
            or not isinstance(proposal['payload'], dict)):
        raise AuthorityError('Unsupported decision proposal envelope')
    return 'automation/decisions/' + KINDS[proposal['kind']] + '/' + canonical_hash(proposal) + '.json'


def api_failure_details(status, headers, output):
    """Expose typed rate-limit metadata and fixed categories, never response text."""
    fields = {}
    for header, name, maximum in (
            (b'x-ratelimit-limit', 'limit', 10**9),
            (b'x-ratelimit-remaining', 'remaining', 10**9),
            (b'x-ratelimit-reset', 'reset', 99999999999),
            (b'retry-after', 'retry-after', 86400)):
        value = headers.get(header)
        if value is not None and re.fullmatch(rb'[0-9]{1,11}', value):
            number = int(value)
            if number <= maximum:
                fields[name] = str(number)
    resource_name = headers.get(b'x-ratelimit-resource')
    if resource_name in (b'core', b'search', b'graphql'):
        fields['resource'] = resource_name.decode('ascii')
    # Error messages may contain credentials or private response data. Inspect
    # only a small bounded JSON body to select a fixed, non-reflecting category.
    message = ''
    body = output.read(8193)
    if len(body) <= 8192:
        try:
            response = json.loads(body)
            if isinstance(response, dict) and isinstance(response.get('message'), str):
                message = response['message'].lower()
        except (ValueError, UnicodeError, RecursionError):
            pass
    if status in (403, 429):
        if fields.get('remaining') == '0':
            fields['category'] = 'primary-rate-limit'
        elif 'secondary rate limit' in message or 'retry-after' in fields:
            fields['category'] = 'secondary-rate-limit'
        elif 'api rate limit exceeded' in message:
            fields['category'] = 'rate-limit'
        elif message == 'resource not accessible by integration':
            fields['category'] = 'permission-denied'
    elif status == 401 and message == 'bad credentials':
        fields['category'] = 'bad-credentials'
    return ''.join('; ' + name + '=' + value for name, value in fields.items())


def github_api(endpoint):
    # Endpoint is constructed from validated repository, PR numbers and hashes.
    # GitHub base64 JSON needs more space than the bounded raw document. Bound
    # the child output before allocating or parsing it, including on API errors.
    def bound_output():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_API_BYTES, MAX_API_BYTES))
    for attempt in range(1, 4):
        details = ''
        with tempfile.TemporaryFile() as output:
            try:
                result = subprocess.run(['gh', 'api', '--method', 'GET', '--include', endpoint],
                                        stdout=output, stderr=subprocess.DEVNULL,
                                        timeout=60, check=False, preexec_fn=bound_output)
            except OSError as error:
                raise AuthorityError('GitHub authority API unavailable') from error
            except subprocess.TimeoutExpired:
                failure = 'timeout'
            else:
                if output.tell() >= MAX_API_BYTES or result.returncode < 0:
                    raise AuthorityError('GitHub authority API output failed or exceeded limit')
                output.seek(0)
                line = output.readline(8193)
                if not line and result.returncode:
                    failure = 'transport'
                else:
                    status = re.fullmatch(rb'HTTP/[0-9.]+ ([0-9]{3})[^\r\n]*\r?\n', line)
                    if not status:
                        raise AuthorityError('Invalid GitHub API status')
                    status = int(status[1])
                    header_bytes = len(line)
                    headers = {}
                    while True:
                        line = output.readline(8193)
                        header_bytes += len(line)
                        if not line or len(line) > 8192 or header_bytes > 64 * 1024:
                            raise AuthorityError('Invalid bounded GitHub API headers')
                        if line in (b'\n', b'\r\n'):
                            break
                        name, separator, value = line.partition(b':')
                        name = name.lower()
                        if separator and name in (b'x-ratelimit-limit', b'x-ratelimit-remaining',
                                                  b'x-ratelimit-reset', b'x-ratelimit-resource', b'retry-after'):
                            # Duplicate diagnostic headers are ambiguous: suppress them.
                            headers[name] = None if name in headers else value.strip()
                    failure = f'HTTP {status}'
                    if status == 200 and result.returncode == 0:
                        try:
                            return json.load(output)
                        except (ValueError, UnicodeError) as error:
                            raise AuthorityError('Invalid GitHub API response') from error
                    details = api_failure_details(status, headers, output)
                    if status not in (408, 429, 500, 502, 503, 504):
                        raise AuthorityError('GitHub authority API failed: ' + endpoint.split('?')[0]
                                             + f' ({failure}; attempt {attempt}{details})')
        # Retry only fresh read requests. No response or authority is cached.
        if attempt == 3:
            raise AuthorityError('GitHub authority API failed: ' + endpoint.split('?')[0]
                                 + f' ({failure}; 3 attempts{details})')
        time.sleep(attempt)


def collection(api, endpoint):
    values = []
    for page in range(1, 11):
        response = api(endpoint + ('&' if '?' in endpoint else '?') + f'per_page=100&page={page}')
        if not isinstance(response, list) or len(response) > 100:
            raise AuthorityError('Invalid bounded GitHub collection')
        values.extend(response)
        if len(response) < 100:
            return values
    raise AuthorityError('GitHub authority collection exceeds bounded pagination')


def merged_event(api, repository, number, pull):
    """Use the completed merge event, never GitHub's preview merge SHA."""
    events = collection(api, f'repos/{repository}/issues/{number}/timeline')
    if any(not isinstance(event, dict) for event in events):
        raise AuthorityError('Invalid authenticated PR timeline')
    merges = [event for event in events if event.get('event') == 'merged']
    if len(merges) != 1:
        raise AuthorityError('Proposal requires one unambiguous completed merge event')
    event = merges[0]
    merged_at = pull.get('merged_at')
    if (type(event.get('id')) is not int or event['id'] < 1
            or not isinstance(event.get('commit_id'), str) or not SHA.fullmatch(event['commit_id'])
            or not isinstance(merged_at, str)
            or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', merged_at)
            or event.get('created_at') != merged_at
            or event.get('commit_url') not in
               (None, f'https://api.github.com/repos/{repository}/commits/{event["commit_id"]}')):
        raise AuthorityError('Completed merge event differs from authenticated PR merge metadata')
    try:
        datetime.datetime.strptime(merged_at, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as error:
        raise AuthorityError('Invalid authenticated PR merge timestamp') from error
    return {key: event[key] for key in ('id', 'commit_id', 'created_at')}


def validate_context(repository, expected_bot):
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
        raise AuthorityError('Invalid repository')
    if not isinstance(expected_bot, str) or not re.fullmatch(r'[A-Za-z0-9_-]+\[bot\]', expected_bot):
        raise AuthorityError('A configured trusted GitHub App bot login is required')


def document_at(api, repository, path, revision):
    if not isinstance(revision, str) or not SHA.fullmatch(revision):
        raise AuthorityError('Content lookup requires immutable commit SHA')
    content = api(f'repos/{repository}/contents/{quote(path, safe="/")}?ref={revision}')
    if (not isinstance(content, dict) or content.get('type') != 'file'
            or content.get('encoding') not in ('base64', 'none')
            or type(content.get('size')) is not int or not 0 < content['size'] <= MAX_PROPOSAL_BYTES
            or not isinstance(content.get('sha'), str) or not SHA.fullmatch(content['sha'])):
        raise AuthorityError('Decision proposal is not a bounded regular Git blob')
    blob = content
    if content['encoding'] == 'none':
        # Contents omits inline data above 1 MiB. Resolve only the exact blob
        # named by immutable-ref metadata; never follow a mutable download URL.
        blob = api(f'repos/{repository}/git/blobs/{content["sha"]}')
        if (not isinstance(blob, dict) or blob.get('sha') != content['sha']
                or type(blob.get('size')) is not int or blob['size'] != content['size']):
            raise AuthorityError('Git blob differs from immutable proposal metadata')
    if blob.get('encoding') != 'base64' or not isinstance(blob.get('content'), str):
        raise AuthorityError('Decision proposal requires encoded Git blob bytes')
    try:
        encoded = blob['content'].replace('\n', '')
        if len(encoded) != 4 * ((content['size'] + 2) // 3):
            raise ValueError('Encoded blob exceeds or differs from declared byte size')
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) != content['size']:
            raise ValueError('Blob size mismatch')
        identity = hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()
        if identity != content['sha']:
            raise ValueError('Git blob object SHA differs from authenticated metadata')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('Duplicate proposal key')
                result[key] = value
            return result
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite proposal number')))
    except (ValueError, TypeError) as error:
        raise AuthorityError('Invalid proposal blob') from error


def approver_members(api):
    """A complete visible, pinned team inventory; 404/API errors never mean empty."""
    endpoint = f'orgs/{APPROVER_ORG}/teams/{APPROVER_TEAM}'
    team = api(endpoint)
    if (not isinstance(team, dict) or type(team.get('id')) is not int
            or team['id'] != APPROVER_TEAM_ID or team.get('slug') != APPROVER_TEAM
            or not isinstance(team.get('organization'), dict) or team['organization'].get('login') != APPROVER_ORG):
        raise AuthorityError('Cannot authenticate the pinned Super Admins approval team')
    users = collection(api, endpoint + '/members?role=all')
    members, ids = {}, set()
    for user in users:
        if (not isinstance(user, dict) or user.get('type') != 'User'
                or not isinstance(user.get('login'), str) or not re.fullmatch(r'[A-Za-z0-9-]+', user['login'])
                or type(user.get('id')) is not int or user['id'] < 1
                or user['login'].lower() in members or user['id'] in ids):
            raise AuthorityError('Invalid complete Super Admins membership inventory')
        members[user['login'].lower()] = user['id']
        ids.add(user['id'])
    return members


def eligible(api, repository, user, members=None):
    if not isinstance(user, dict) or user.get('type') != 'User' or not isinstance(user.get('login'), str):
        return False
    login = user['login']
    if (not re.fullmatch(r'[A-Za-z0-9-]+', login)
            or type(user.get('id')) is not int or user['id'] < 1):
        raise AuthorityError('Invalid immutable human reviewer identity')
    members = approver_members(api) if members is None else members
    if login.lower() not in members:
        return False
    if user['id'] != members[login.lower()]:
        raise AuthorityError('Reviewer identity differs from current Super Admins member')
    membership = api(f'orgs/{APPROVER_ORG}/teams/{APPROVER_TEAM}/memberships/{login}')
    if (not isinstance(membership, dict) or membership.get('state') not in ('active', 'pending')
            or membership.get('role') not in ('member', 'maintainer')):
        raise AuthorityError('Invalid current Super Admins membership')
    if membership['state'] != 'active':
        return False
    permission = api(f'repos/{repository}/collaborators/{login}/permission')
    if not isinstance(permission, dict):
        raise AuthorityError('Invalid current reviewer permission')
    # Team membership narrows authority; it never grants repository privileges.
    return permission.get('role_name', permission.get('permission')) in ('maintain', 'admin')


def approval(api, repository, number, head):
    members = approver_members(api)
    reviews = collection(api, f'repos/{repository}/pulls/{number}/reviews')
    latest = {}
    for review in reviews:
        if (not isinstance(review, dict) or type(review.get('id')) is not int or review['id'] < 1
                or not isinstance(review.get('user'), dict)):
            raise AuthorityError('Invalid authenticated PR review record')
        if review.get('state') not in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'):
            continue
        user = review['user']
        if user.get('type') == 'Bot':
            continue
        login, user_id = user.get('login'), user.get('id')
        if (user.get('type') != 'User' or not isinstance(login, str)
                or not re.fullmatch(r'[A-Za-z0-9-]+', login)
                or type(user_id) is not int or user_id < 1):
            raise AuthorityError('Review lacks immutable authenticated human identity')
        if user_id not in latest or latest[user_id]['id'] < review['id']:
            latest[user_id] = review
    accepted = []
    for review in latest.values():
        if not eligible(api, repository, review['user'], members):
            continue
        if review['state'] == 'CHANGES_REQUESTED':
            raise HumanDecisionRequired('Eligible Super Admin has an unresolved changes-requested review')
        if review['state'] == 'APPROVED' and review.get('commit_id') == head:
            accepted.append(review)
    if not accepted:
        raise HumanDecisionRequired('An active Super Admin with maintain/admin access must approve the exact current proposal PR head')
    selected = sorted(accepted, key=lambda value: value['id'])[-1]
    if approver_members(api) != members:
        raise AuthorityError('Super Admins membership changed during authorization')
    if not eligible(api, repository, selected['user'], members):
        raise HumanDecisionRequired('Selected Super Admin approval is no longer eligible')
    return selected


def verify_proposal(proposal, pr, repository, expected_bot, require_merged=True, github=None,
                    allowed_paths=None, require_live_review=True):
    """Return API-derived authority; callers separately validate scan/release payload semantics.

    No self-reported PR ID, approver, hash or signature inside a proposal grants authority.
    Current active Super Admins membership and maintain/admin access are required; there is no TTL.
    """
    validate_context(repository, expected_bot)
    if not require_live_review and not require_merged:
        raise AuthorityError('Historical provenance cannot authorize an open proposal')
    path = proposal_path(proposal)
    digest = canonical_hash(proposal)
    if isinstance(pr, bool) or not str(pr).isdigit() or int(pr) < 1:
        raise AuthorityError('Invalid proposal PR number')
    number = int(pr)
    api = github or github_api
    endpoint = f'repos/{repository}/pulls/{number}'
    pull = api(endpoint)
    if not isinstance(pull, dict):
        raise AuthorityError('Invalid PR response')
    head = pull.get('head', {}).get('sha', '')
    author = pull.get('user', {})
    if (pull.get('number') != number or author.get('type') != 'Bot' or author.get('login') != expected_bot
            or pull.get('base', {}).get('repo', {}).get('full_name') != repository
            or pull.get('head', {}).get('repo', {}).get('full_name') != repository
            or pull.get('base', {}).get('ref') != 'main' or not SHA.fullmatch(head)):
        raise AuthorityError('Proposal must be authored by the configured bot in this repository targeting main')
    if not pull.get('merged') and (require_merged or pull.get('state') != 'open'):
        raise AuthorityError('Proposal is not in the required merged/open state')
    files = collection(api, endpoint + '/files')
    permitted = set(allowed_paths) if allowed_paths is not None else {path}
    if path not in permitted or not files or len(files) != pull.get('changed_files'):
        raise AuthorityError('Incomplete or inconsistent proposal file inventory')
    if any(not isinstance(item, dict) or item.get('filename') not in permitted
           or item.get('status') not in ('added', 'modified') for item in files):
        raise AuthorityError('Proposal changes unexpected, renamed or deleted files')
    if path not in {item['filename'] for item in files}:
        raise AuthorityError('Proposal file was not changed by the approved PR')
    if canonical_hash(document_at(api, repository, path, head)) != digest:
        raise AuthorityError('Local proposal differs from exact reviewed PR head')
    merge = None
    merge_provenance = None
    if pull.get('merged'):
        merge_provenance = merged_event(api, repository, number, pull)
        merge = merge_provenance['commit_id']
        if canonical_hash(document_at(api, repository, path, merge)) != digest:
            raise AuthorityError('Merged proposal differs from reviewed proposal')
        main = api(f'repos/{repository}/git/ref/heads/main')
        current = main.get('object', {}).get('sha', '') if isinstance(main, dict) else ''
        if not SHA.fullmatch(current):
            raise AuthorityError('Cannot establish current protected main')
        comparison = api(f'repos/{repository}/compare/{merge}...{current}')
        if not isinstance(comparison, dict) or comparison.get('status') not in ('ahead', 'identical'):
            raise AuthorityError('Proposal merge is not an ancestor of current main')
        if canonical_hash(document_at(api, repository, path, current)) != digest:
            raise AuthorityError('Decision proposal is no longer unchanged on main')
    review = approval(api, repository, number, head) if require_live_review else None
    # Detect changed proposal heads/merge state while authority was being checked.
    latest = api(endpoint)
    if (not isinstance(latest, dict) or latest.get('head', {}).get('sha') != head
            or latest.get('merged') != pull.get('merged') or latest.get('state') != pull.get('state')
            or latest.get('merged_at') != pull.get('merged_at')
            or latest.get('merge_commit_sha') != pull.get('merge_commit_sha')):
        raise AuthorityError('Proposal PR changed during authorization')
    if merge_provenance is not None and merged_event(api, repository, number, latest) != merge_provenance:
        raise AuthorityError('Proposal merge event changed during authorization')
    if review is not None and not eligible(api, repository, review['user']):
        raise HumanDecisionRequired('Super Admin approval was withdrawn during authorization')
    return {'schema': 1, 'status': 'authorized' if review is not None else 'historical-provenance', 'repository': repository,
            'proposalHash': digest, 'path': path, 'pullRequest': number,
            'reviewId': review['id'] if review is not None else None, 'reviewer': review['user']['login'] if review is not None else None,
            'reviewedHead': head, 'mergeCommit': merge if pull.get('merged') else None,
            'permissionPolicy': 'current-super-admins-and-maintain-or-admin' if review is not None else 'immutable-bot-merge-provenance',
            'approverTeam': {'organization': APPROVER_ORG, 'slug': APPROVER_TEAM, 'id': APPROVER_TEAM_ID}}


def find_origin_pr(proposal, repository, expected_bot, github=None):
    """Derive provenance from GitHub commit/PR association, not self-reported fields."""
    validate_context(repository, expected_bot)
    api = github or github_api
    path = proposal_path(proposal)
    commits = api(f'repos/{repository}/commits?path={quote(path, safe="/")}&sha=main&per_page=1')
    if not isinstance(commits, list) or len(commits) != 1 or not SHA.fullmatch(commits[0].get('sha', '')):
        raise AuthorityError('Cannot establish proposal file history on main')
    pulls = collection(api, f'repos/{repository}/commits/{commits[0]["sha"]}/pulls')
    candidates = [p for p in pulls if isinstance(p, dict) and p.get('merged_at')
                  and p.get('user', {}).get('login') == expected_bot
                  and p.get('base', {}).get('repo', {}).get('full_name') == repository
                  and p.get('base', {}).get('ref') == 'main']
    if len(candidates) != 1:
        raise AuthorityError('Proposal history has ambiguous or missing merged bot PR provenance')
    return candidates[0]['number']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proposal', required=True, type=Path)
    parser.add_argument('--pr', type=int, help='Omit for merged proposals to derive origin through GitHub')
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--bot-login', default=os.environ.get('FINITE_REVIEW_BOT_LOGIN'))
    parser.add_argument('--allow-open', action='store_true', help='PR/merge-queue check only; never release authorization')
    parser.add_argument('--allow-path', action='append', help='Additional reviewed packet/report paths allowed in this proposal PR')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        proposal = load_json(args.proposal)
        pr = args.pr if args.pr else find_origin_pr(proposal, args.repository, args.bot_login)
        paths = [proposal_path(proposal), *(args.allow_path or [])]
        result = verify_proposal(proposal, pr, args.repository, args.bot_login,
                                 not args.allow_open, allowed_paths=paths)
        code = 0
    except (AuthorityError, TechnicalError, ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError) as error:
        result, code = {'schema': 1, 'status': 'unauthorized', 'error': str(error)}, 2
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return code


if __name__ == '__main__':
    sys.exit(main())
