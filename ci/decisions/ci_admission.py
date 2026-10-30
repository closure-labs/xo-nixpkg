#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Approve CI execution for live trusted identities; never approve PR reviews."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from decision_authority import AuthorityError, HumanDecisionRequired, approval, collection, eligible, github_api
import dependency_update as dependency

COLLECTOR = '.github/workflows/decision-events.yml'
AUTHORITY = '.github/workflows/decision-authority.yml'


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
    return (type(run.get('id')) is int and run['id'] == run_id
            and (run.get('event') == 'pull_request'
                 or run.get('event') == 'pull_request_review' and run.get('path') == COLLECTOR)
            and run.get('status') == 'completed'
            and run.get('conclusion') == 'action_required'
            and run.get('repository', {}).get('id') == policy['repositoryId']
            and run.get('repository', {}).get('full_name') == policy['repository']
            and run.get('path') in policy['workflows']
            and isinstance(run.get('head_sha'), str)
            and re.fullmatch(r'[0-9a-f]{40}', run['head_sha'])
            and type(run.get('workflow_id')) is int and run['workflow_id'] > 0
            and type(run.get('run_attempt')) is int and run['run_attempt'] > 0)


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
    if (workflow.get('id') != run['workflow_id'] or workflow.get('path') != run['path']
            or workflow.get('state') != 'active'):
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
        if pull.get('number') != number:
            raise AuthorityError('CI PR identity differs from native association')
        if not matches(pull, run, policy):
            continue
        # A trusted PR author is not a blanket grant to an unrelated pusher or
        # rerun actor. Draft state is deliberately irrelevant to CI admission.
        users = [pull.get('user'), run.get('actor'), run.get('triggering_actor')]
        context = None
        if dependency.official(pull):
            if (run.get('head_repository', {}).get('id') != policy['repositoryId']
                    or run.get('head_repository', {}).get('full_name') != policy['repository']):
                return 'dependency-origin-mismatch'
            if policy.get('dependabot') != {
                    'login': dependency.BOT['login'], 'id': dependency.BOT['id'],
                    'family': 'github-actions-pins', 'sameRepositoryOnly': True,
                    'requiresCurrentHeadHumanApproval': True}:
                raise AuthorityError('Dependency CI admission differs from the reviewed policy')
            # This is a narrow execution exception, not a new proposal author
            # or merge approval. The complete immutable delta must be pins only.
            try:
                context = dependency.inspect(api, policy['repository'], pull)
                dependency.classify(api, context)
            except dependency.UnsupportedFamily as error:
                print(json.dumps({'pullRequest': number, 'dependencyPolicy': str(error)}))
                return 'unsupported-dependency-family'
            actors = users[1:]
            if not all(dependency.official({'user': user}) or trusted(api, policy, user) for user in actors):
                continue
            try:
                approval(api, policy['repository'], number, run['head_sha'])
            except HumanDecisionRequired:
                return 'human-review-required'
            dependency.revalidate(api, policy['repository'], context)
        else:
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
        if context is not None:
            # Immutable bytes need no second parse. Mutable review, eligibility,
            # actors, PR/base/head and run attempt must still be current.
            if not all(dependency.official({'user': user}) or trusted(api, policy, user) for user in actors):
                return 'identity-revoked'
            try:
                approval(api, policy['repository'], number, run['head_sha'])
            except HumanDecisionRequired:
                return 'human-review-required'
            dependency.revalidate(api, policy['repository'], context)
            final_run = api(endpoint)
            if run_binding(final_run) != run_binding(run) or not valid_run(final_run, policy, run_id):
                return 'binding-changed'
        # Approval endpoint only. No reviews, dispatch, branch writes or queue.
        # Never retry an ambiguous mutation: the next invocation reads anew.
        post(endpoint + '/approve')
        return 'approved'
    return 'no-trusted-current-pr'


def pending_runs(api, policy, head=None):
    # Include held review collectors too; approve_run restricts their exact path.
    endpoint = 'repos/' + policy['repository'] + '/actions/runs?status=action_required'
    if head is not None:
        if not isinstance(head, str) or not re.fullmatch(r'[0-9a-f]{40}', head):
            raise AuthorityError('Invalid CI discovery head')
        endpoint += '&head_sha=' + head
    result = []
    for page in range(1, 11):
        response = api(endpoint + f'&per_page=100&page={page}')
        runs = response.get('workflow_runs')
        if not isinstance(runs, list) or len(runs) > 100:
            raise AuthorityError('Invalid bounded pending CI inventory')
        if any(not isinstance(run, dict) or type(run.get('id')) is not int or run['id'] < 1 for run in runs):
            raise AuthorityError('Invalid pending CI run identity')
        result.extend(run['id'] for run in runs)
        if len(runs) < 100:
            if len(set(result)) != len(result):
                raise AuthorityError('Duplicate pending CI run identity')
            return result
    raise AuthorityError('Pending CI inventory exceeds bounded pagination')


def wake_runs(api, policy, run_id):
    """A native completion is only a wake-up, never cached authorization."""
    if type(run_id) is not int or run_id < 1:
        raise AuthorityError('Invalid CI wake-up ID')
    prefix = 'repos/' + policy['repository']
    run = api(f'{prefix}/actions/runs/{run_id}')
    if valid_run(run, policy, run_id):
        return [run_id]
    if (type(run.get('id')) is not int or run['id'] != run_id
            or type(run.get('run_attempt')) is not int or run['run_attempt'] < 1
            or run.get('repository', {}).get('id') != policy['repositoryId']
            or run.get('repository', {}).get('full_name') != policy['repository']
            or run.get('status') != 'completed' or type(run.get('workflow_id')) is not int or run['workflow_id'] < 1
            or not isinstance(run.get('head_sha'), str) or not re.fullmatch(r'[0-9a-f]{40}', run['head_sha'])):
        raise AuthorityError('Invalid native CI wake-up identity')
    workflow = api(f'{prefix}/actions/workflows/{run["workflow_id"]}')
    if workflow.get('id') != run['workflow_id'] or workflow.get('path') != run.get('path') or workflow.get('state') != 'active':
        raise AuthorityError('CI wake-up workflow identity mismatch')
    if (run.get('path') == COLLECTOR and run.get('event') == 'pull_request_review'
            and run.get('conclusion') == 'success'):
        candidates = collection(api, f'{prefix}/commits/{run["head_sha"]}/pulls')
        if len(candidates) > 16:
            raise AuthorityError('Review wake-up PR inventory exceeds bound')
        current = []
        for candidate in candidates:
            number = candidate.get('number') if isinstance(candidate, dict) else None
            if type(number) is not int or number < 1:
                raise AuthorityError('Invalid review wake-up PR identity')
            pull = api(f'{prefix}/pulls/{number}')
            if pull.get('number') != number:
                raise AuthorityError('Review wake-up PR identity differs from association')
            if matches(pull, run, policy):
                current.append(number)
        if len(current) != 1:
            raise AuthorityError('Review wake-up lacks one current native PR')
        return pending_runs(api, policy, run['head_sha'])
    if (run.get('path') == AUTHORITY and run.get('event') == 'workflow_run'
            and run.get('head_branch') == 'main'
            and run.get('head_repository', {}).get('id') == policy['repositoryId']
            and run.get('head_repository', {}).get('full_name') == policy['repository']
            and run.get('conclusion') in ('success', 'failure')):
        return pending_runs(api, policy)
    raise AuthorityError('Unsupported CI wake-up event')


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
    run_ids = wake_runs(github_api, policy, int(event_run)) if event_run else pending_runs(github_api, policy)
    for run_id in run_ids:
        print(json.dumps({'runId': run_id, 'result': approve_run(
            github_api, post_approval, policy, run_id)}, sort_keys=True))


if __name__ == '__main__':
    main()
