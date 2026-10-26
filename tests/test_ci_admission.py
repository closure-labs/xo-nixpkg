#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Trusted CI approval must not grant merge authority or follow stale heads."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / ('nix/automation' if (ROOT / 'nix/automation').is_dir() else 'ci')
sys.path.insert(0, str(SOURCE / 'decisions'))
import ci_admission as admission

POLICY = json.loads((SOURCE / 'ci-admission-policy.json').read_text())
BOT = dict(POLICY['bot'], type='Bot')
HUMAN = {'login': 'maintainer', 'id': 10, 'type': 'User'}
REPO = {'id': POLICY['repositoryId'], 'full_name': POLICY['repository']}
SHA = 'a' * 40


class API:
    def __init__(self):
        self.run = dict(id=42, run_attempt=1, event='pull_request', conclusion='action_required',
                        repository=REPO, head_repository={'id': 91}, head_branch='change', head_sha=SHA,
                        path='.github/workflows/ci.yml', workflow_id=5, actor=BOT, triggering_actor=BOT)
        self.pull = dict(number=7, state='open', draft=True, user=BOT,
                         base={'ref': 'main', 'repo': REPO},
                         head={'sha': SHA, 'ref': 'change', 'repo': {'id': 91}})
        self.calls, self.posts = [], []
        self.mutate = lambda endpoint: None
        self.member, self.permission = True, 'admin'
        self.workflow = {'path': self.run['path'], 'state': 'active'}

    def __call__(self, endpoint):
        self.calls.append(endpoint)
        self.mutate(endpoint)
        if endpoint.endswith('/actions/runs/42'):
            return deepcopy(self.run)
        if endpoint.endswith('/pulls/7'):
            return deepcopy(self.pull)
        if '/commits/' in endpoint:
            return [{'number': 7}]
        if '/actions/workflows/' in endpoint:
            return deepcopy(self.workflow)
        if endpoint.endswith('/teams/super-admins'):
            return {'id': 20196962, 'slug': 'super-admins', 'organization': {'login': 'closure-labs'}}
        if '/members?' in endpoint:
            return [HUMAN] if self.member else []
        if '/memberships/' in endpoint:
            return {'state': 'active' if self.member else 'pending', 'role': 'member'}
        if endpoint.endswith('/permission'):
            return {'role_name': self.permission}
        raise AssertionError(endpoint)

    def approve(self):
        return admission.approve_run(self, self.posts.append, POLICY, 42)

    def human(self):
        self.pull['user'] = HUMAN
        self.run.update(actor=HUMAN, triggering_actor=HUMAN)


class Admission(unittest.TestCase):
    def test_bot_draft_and_ready(self):
        for draft in (True, False):
            api = API(); api.pull['draft'] = draft
            self.assertEqual(api.approve(), 'approved')
            self.assertEqual(api.posts, [f'repos/{POLICY["repository"]}/actions/runs/42/approve'])

    def test_super_admin_draft_and_ready(self):
        for draft in (True, False):
            api = API(); api.human(); api.pull['draft'] = draft
            self.assertEqual(api.approve(), 'approved')
            self.assertGreaterEqual(sum('/memberships/' in call for call in api.calls), 2)

    def test_impostor_bot_and_untrusted_author(self):
        for user in (dict(BOT, id=1), dict(BOT, type='User'), dict(HUMAN, id=11)):
            api = API(); api.pull['user'] = user
            try:
                self.assertNotEqual(api.approve(), 'approved')
            except admission.AuthorityError:
                pass
            self.assertFalse(api.posts)

    def test_untrusted_pusher_or_rerunner(self):
        for field in ('actor', 'triggering_actor'):
            api = API(); api.run[field] = dict(BOT, id=1)
            self.assertNotEqual(api.approve(), 'approved'); self.assertFalse(api.posts)

    def test_revoked_membership_or_repository_permissions(self):
        for field, value in [('member', False), ('permission', 'write'), ('permission', 'read')]:
            api = API(); api.human(); setattr(api, field, value)
            self.assertNotEqual(api.approve(), 'approved'); self.assertFalse(api.posts)

    def test_revocation_during_checks(self):
        api = API(); api.human()
        def mutate(endpoint):
            if sum('/members?' in call for call in api.calls) >= 4:
                api.member = False
        api.mutate = mutate
        self.assertEqual(api.approve(), 'identity-revoked'); self.assertFalse(api.posts)

    def test_wrong_run_event_repository_workflow_or_status(self):
        for field, value in [('event','push'), ('repository', {'id': 3}),
                             ('path','.github/workflows/publish.yml'), ('conclusion','success'),
                             ('head_sha','not-a-sha')]:
            api = API(); api.run[field] = value
            self.assertNotEqual(api.approve(), 'approved'); self.assertFalse(api.posts)

    def test_workflow_identity_mismatch(self):
        api = API(); api.workflow['path'] = '.github/workflows/publish.yml'
        self.assertEqual(api.approve(), 'workflow-mismatch'); self.assertFalse(api.posts)

    def test_closed_stale_foreign_or_non_main_pr(self):
        for change in ('closed','sha','repo','base','branch'):
            api = API()
            if change == 'closed': api.pull['state'] = 'closed'
            if change == 'sha': api.pull['head']['sha'] = 'b'*40
            if change == 'repo': api.pull['head']['repo']['id'] = 92
            if change == 'base': api.pull['base']['ref'] = 'other'
            if change == 'branch': api.pull['head']['ref'] = 'other'
            self.assertNotEqual(api.approve(), 'approved'); self.assertFalse(api.posts)

    def test_head_changes_before_mutation(self):
        api = API()
        def mutate(endpoint):
            if endpoint.endswith('/pulls/7') and api.calls.count(endpoint) == 2:
                api.pull['head']['sha'] = 'b'*40
        api.mutate = mutate
        self.assertEqual(api.approve(), 'binding-changed'); self.assertFalse(api.posts)

    def test_run_attempt_changes_before_mutation(self):
        api = API()
        def mutate(endpoint):
            if endpoint.endswith('/actions/runs/42') and api.calls.count(endpoint) == 2:
                api.run['run_attempt'] = 2
        api.mutate = mutate
        self.assertEqual(api.approve(), 'binding-changed'); self.assertFalse(api.posts)

    def test_api_failure_never_approves(self):
        api = API()
        def fail(endpoint): raise admission.AuthorityError('Unavailable')
        api.mutate = fail
        with self.assertRaises(admission.AuthorityError): api.approve()
        self.assertFalse(api.posts)

    def test_ambiguous_post_not_retried(self):
        api = API(); calls = []
        def fail(endpoint):
            calls.append(endpoint)
            raise TimeoutError('Lost acknowledgement')
        with self.assertRaises(TimeoutError): admission.approve_run(api, fail, POLICY, 42)
        self.assertEqual(len(calls), 1)

    def test_pagination_is_complete_and_bounded(self):
        calls = []
        def api(endpoint):
            calls.append(endpoint)
            return {'workflow_runs': [{'id': i} for i in range(100)] if len(calls)==1 else [{'id': 200}]}
        self.assertEqual(len(admission.pending_runs(api, POLICY)), 101)
        with self.assertRaises(admission.AuthorityError):
            admission.pending_runs(lambda _: {'workflow_runs':[{'id':i} for i in range(100)]}, POLICY)

    def test_workflow_executes_only_protected_controller(self):
        workflow = (ROOT/'.github/workflows/ci-admission.yml').read_text()
        self.assertIn('ref: main', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('ci:admit-trusted', workflow)
        self.assertIn("cron: '*/15 * * * *'", workflow)
        for forbidden in ('head.sha', 'pull_request_target:', 'permission-contents: write',
                          'permission-pull-requests: write', 'permission-checks: write', 'download-artifact'):
            self.assertNotIn(forbidden, workflow)


if __name__ == '__main__':
    unittest.main()
