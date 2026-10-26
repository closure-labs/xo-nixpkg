#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Approve CI execution for live trusted identities; never approve PR reviews."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from decision_authority import AuthorityError, collection, eligible, github_api


def trusted(api, policy, user):
    if not isinstance(user, dict):
        return False
    bot = policy['bot']
    if user.get('type') == 'Bot':
        return (user.get('login') == bot['login'] and type(user.get('id')) is int
                and user['id'] == bot['id'])
    return eligible(api, policy['repository'], user)


def run_binding(run):
    return {key: run.get(key) for key in (
        'id', 'run_attempt', 'event', 'head_sha', 'head_branch', 'head_repository',
        'repository', 'workflow_id', 'path', 'actor', 'triggering_actor')}


def valid_run(run, policy, run_id):
    return (run.get('id') == run_id and run.get('event') == 'pull_request'
            and run.get('conclusion') == 'action_required'
            and run.get('repository', {}).get('id') == policy['repositoryId']
            and run.get('repository', {}).get('full_name') == policy['repository']
            and run.get('path') in policy['workflows']
            and isinstance(run.get('head_sha'), str)
            and re.fullmatch(r'[0-9a-f]{40}', run['head_sha'])
            and type(run.get('workflow_id')) is int
            and type(run.get('run_attempt')) is int)


def pull_binding(pull):
    return {key: pull.get(key) for key in ('number', 'state', 'user', 'head', 'base')}


def matches(pull, run, policy):
    head, base = pull.get('head', {}), pull.get('base', {})
    return (pull.get('state') == 'open' and type(pull.get('number')) is int
            and base.get('ref') == 'main'
            and (base.get('repo') or {}).get('id') == policy['repositoryId']
            and head.get('sha') == run['head_sha'] and head.get('ref') == run['head_branch']
            and type((head.get('repo') or {}).get('id')) is int
            and (head.get('repo') or {}).get('id') == (run.get('head_repository') or {}).get('id'))


def approve_run(api, post, policy, run_id):
    """Read twice around identity checks; no stale successful authorization reuse."""
    if type(run_id) is not int or run_id < 1:
        raise AuthorityError('Invalid CI run ID')
    prefix = 'repos/' + policy['repository']
    endpoint = f'{prefix}/actions/runs/{run_id}'
    run = api(endpoint)
    if not valid_run(run, policy, run_id):
        return 'not-pending-ci'
    workflow = api(f'{prefix}/actions/workflows/{run["workflow_id"]}')
    if workflow.get('path') != run['path'] or workflow.get('state') != 'active':
        return 'workflow-mismatch'
    # Fork workflow events can omit pull_requests. Resolve the immutable commit
    # through GitHub, then authenticate each candidate with a fresh PR read.
    candidates = collection(api, f'{prefix}/commits/{run["head_sha"]}/pulls')
    for candidate in candidates:
        number = candidate.get('number')
        if type(number) is not int or number < 1:
            raise AuthorityError('Invalid associated PR number')
        pull_endpoint = f'{prefix}/pulls/{number}'
        pull = api(pull_endpoint)
        if not matches(pull, run, policy):
            continue
        # A trusted PR author is not a blanket grant to an unrelated pusher or
        # rerun actor. Draft state is deliberately irrelevant to CI admission.
        users = [pull.get('user'), run.get('actor'), run.get('triggering_actor')]
        if not all(trusted(api, policy, user) for user in users):
            continue
        if not all(trusted(api, policy, user) for user in users):
            return 'identity-revoked'
        current_pull = api(pull_endpoint)
        current_run = api(endpoint)
        if (pull_binding(current_pull) != pull_binding(pull)
                or not matches(current_pull, current_run, policy)
                or run_binding(current_run) != run_binding(run)
                or not valid_run(current_run, policy, run_id)):
            return 'binding-changed'
        # Approval endpoint only. No reviews, dispatch, branch writes or queue.
        # Never retry an ambiguous mutation: the next invocation reads anew.
        post(endpoint + '/approve')
        return 'approved'
    return 'no-trusted-current-pr'


def pending_runs(api, policy):
    endpoint = 'repos/' + policy['repository'] + '/actions/runs?event=pull_request&status=action_required'
    result = []
    for page in range(1, 11):
        response = api(endpoint + f'&per_page=100&page={page}')
        runs = response.get('workflow_runs')
        if not isinstance(runs, list) or len(runs) > 100:
            raise AuthorityError('Invalid bounded pending CI inventory')
        result.extend(run['id'] for run in runs)
        if len(runs) < 100:
            return result
    raise AuthorityError('Pending CI inventory exceeds bounded pagination')


def post_approval(endpoint):
    subprocess.run(['gh', 'api', '--method', 'POST', endpoint], check=True,
                   stdout=subprocess.DEVNULL, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True)
    args = parser.parse_args()
    policy = json.loads(Path(args.policy).read_text())
    if (policy.get('schema') != 1 or policy['repository'] != os.environ.get('GITHUB_REPOSITORY')
            or not re.fullmatch(r'closure-labs/(maestro|xo-nixpkg)', policy['repository'])):
        raise AuthorityError('CI admission policy repository mismatch')
    event_run = os.environ.get('CI_ADMISSION_RUN_ID', '')
    run_ids = [int(event_run)] if event_run else pending_runs(github_api, policy)
    for run_id in run_ids:
        print(json.dumps({'runId': run_id, 'result': approve_run(
            github_api, post_approval, policy, run_id)}, sort_keys=True))


if __name__ == '__main__':
    main()
