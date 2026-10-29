#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci/decisions'))
spec = importlib.util.spec_from_file_location('check', ROOT / 'ci/decisions/check.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
spec = importlib.util.spec_from_file_location('fixtures', ROOT / 'tests/decisions/test_authority.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
REPO, BOT, HEAD, MERGE = fixtures.REPO, fixtures.BOT, fixtures.HEAD, fixtures.MERGE


class GitHub(fixtures.GitHub):
    def __init__(self):
        super().__init__()
        self.pr.update(merged=False, state='open', merge_commit_sha=None)
        self.collector = {'path': mod.COLLECTOR, 'repository': {'full_name': REPO},
                          'status': 'completed', 'conclusion': 'success', 'event': 'pull_request',
                          'head_sha': HEAD, 'head_branch': 'feature', 'pull_requests': [{'number': 7}]}
        self.head_tree = {'truncated': False, 'tree': [{'path': self.files[0]['filename'],
                          'type': 'blob', 'mode': '100644', 'sha': 'd' * 40}]}
        self.queue_tree = self.head_tree
        self.queue_sha = MERGE
        self.queue_refs = []

    def __call__(self, endpoint):
        if '/git/matching-refs/heads/gh-readonly-queue/' in endpoint:
            return self.queue_refs
        if '/actions/runs/' in endpoint:
            return self.collector
        if endpoint.endswith('?state=open&base=main&per_page=100&page=1'):
            return [{'number': 7}]
        if '/git/ref/heads/gh-readonly-queue/' in endpoint:
            return {'object': {'sha': self.queue_sha}}
        if endpoint == f'repos/{REPO}/git/trees/{HEAD}?recursive=1':
            return self.head_tree
        if endpoint == f'repos/{REPO}/git/trees/{MERGE}?recursive=1':
            return self.queue_tree
        return super().__call__(endpoint)


class Checks(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(mod, 'validate_proposal_packet', return_value={})
        self.packet_validator = patcher.start()
        self.addCleanup(patcher.stop)

    def test_regular_pr_passes_without_approval(self):
        api = GitHub()
        api.files = [{'filename': 'recipes/finite.yml', 'status': 'modified'}]
        api.reviews = []
        self.assertEqual(mod.check_pr(REPO, 7, BOT, github=api)['status'], 'not-required')

    def test_governance_requires_current_exact_human_review(self):
        api = GitHub()
        api.files = [{'filename': '.github/workflows/build.yml', 'status': 'modified'}]
        self.assertEqual(mod.check_pr(REPO, 7, BOT, github=api)['status'], 'authorized')
        api.reviews = []
        with self.assertRaises(mod.authority.AuthorityError):
            mod.check_pr(REPO, 7, BOT, github=api)

    def test_human_governance_author_allowed_but_human_proposal_author_rejected(self):
        api = GitHub()
        api.pr['user'] = {'type': 'User', 'login': 'maintainer'}
        with self.assertRaises(mod.authority.AuthorityError):
            mod.check_pr(REPO, 7, BOT, github=api)
        api.files = [{'filename': 'scripts/bluebuild/security-policy.py', 'status': 'modified'}]
        self.assertEqual(mod.check_pr(REPO, 7, BOT, github=api)['status'], 'authorized')

    def test_exact_canonical_bot_proposal(self):
        self.assertEqual(mod.check_pr(REPO, 7, BOT, github=GitHub())['status'], 'authorized')

    def test_packet_validation_is_required_after_authority(self):
        self.packet_validator.side_effect = mod.authority.AuthorityError('Invalid immutable scan packet')
        with self.assertRaises(mod.authority.AuthorityError):
            mod.check_pr(REPO, 7, BOT, github=GitHub())
        self.packet_validator.assert_called_once_with(fixtures.PROPOSAL)

    def test_renamed_governed_path_cannot_hide_review_requirement(self):
        api = GitHub()
        api.files = [{'filename': 'docs/policy.txt', 'previous_filename': 'scripts/ci/decision-authority.py', 'status': 'renamed'}]
        api.reviews = []
        with self.assertRaises(mod.authority.AuthorityError):
            mod.check_pr(REPO, 7, BOT, github=api)

    def test_queue_requires_exact_reviewed_governed_tree(self):
        api = GitHub()
        self.assertEqual(mod.check_pr(REPO, 7, BOT, MERGE, api)['status'], 'authorized')
        api.queue_tree = {'truncated': False, 'tree': []}
        with self.assertRaises(mod.authority.AuthorityError):
            mod.check_pr(REPO, 7, BOT, MERGE, api)

    def test_queue_truncation_fails_closed(self):
        api = GitHub()
        api.queue_tree = {'truncated': True, 'tree': []}
        with self.assertRaises(mod.authority.AuthorityError):
            mod.check_pr(REPO, 7, BOT, MERGE, api)

    def test_collector_metadata_only_and_review_fallback(self):
        api = GitHub()
        self.assertEqual(mod.collector_targets(api.collector, REPO, api), [(7, None)])
        api.collector.update(event='pull_request_review', pull_requests=[])
        self.assertEqual(mod.collector_targets(api.collector, REPO, api), [(7, None)])
        api.collector['path'] = '.github/workflows/attacker.yml'
        with self.assertRaises(mod.authority.AuthorityError):
            mod.collector_targets(api.collector, REPO, api)

    def test_queue_identity_and_changed_ref_rejected(self):
        api = GitHub()
        api.collector.update(event='merge_group', head_branch='gh-readonly-queue/main/pr-7-abcdef0', head_sha=MERGE)
        self.assertEqual(mod.collector_targets(api.collector, REPO, api), [(7, MERGE)])
        api.queue_sha = HEAD
        with self.assertRaises(mod.authority.AuthorityError):
            mod.collector_targets(api.collector, REPO, api)
        api.collector['head_branch'] = 'attacker/pr-7-abcdef0'
        with self.assertRaises(mod.authority.AuthorityError):
            mod.collector_targets(api.collector, REPO, api)

    def test_app_origin_checked_and_missing_approval_posts_failure(self):
        api = GitHub()
        api.reviews = []
        calls = []
        def post(endpoint, body):
            calls.append((endpoint, body))
            return {'app': {'id': 123}}
        result = mod.run_checks(REPO, 1, BOT, 123, api, post)
        self.assertEqual(result['checks'][0]['status'], 'review-required')
        self.assertEqual(calls[0][1]['conclusion'], 'failure')
        with self.assertRaises(mod.authority.AuthorityError):
            mod.run_checks(REPO, 1, BOT, 999, api, post)

    def test_security_authority_boundary_paths(self):
        for path in ('scripts/ci/applicability-evidence.py', 'scripts/bluebuild/future-scan-helper.py', 'flake.lock', 'flake.nix', 'cosign.pub', 'lib/mk-pkgs.nix',
                     'lib/project-policy.nix', 'lib/secretspec.nix', 'sources/bluefin-trust.json',
                     'sources/bluefin.pub', 'sources/cosign-runtime.json', 'secretspec.toml', 'lib/ci-tools.nix', 'lib/ci-secrets.nix',
                     'scripts/ci/security_decisions.py', '.github/actions/setup-nix/action.yml',
                     'scripts/bluebuild/publication.py', 'scripts/ci/release-recovery.py',
                     'automation/github/repository-security.json'):
            self.assertTrue(mod.governed(path), path)
        for boundary in ('verify-security-admission.py', 'reconcile-decisions.py',
                         'verify-attestation-subject.py', 'inventory-evidence.py'):
            self.assertTrue(mod.governed('scripts/ci/' + boundary))
        self.assertTrue(mod.governed('scripts/ci/decision_revocation.py'))
        self.assertTrue(mod.governed('scripts/ci/execute-release-set.py'))
        for path in ('.gitleaks.toml', 'gitleaks.toml', '.gitleaksignore'):
            self.assertTrue(mod.governed(path), path)
        self.assertFalse(mod.governed('docs/README.md'))

    def test_discovery_pins_live_head_not_old_event_head(self):
        api = GitHub()
        api.collector.update(event='pull_request_review', head_sha='f' * 40,
                             created_at='2020-01-01T00:00:00Z')
        self.assertEqual(mod.resolve_targets(REPO, 1, api),
                         {'include': [{'number': 7, 'head': HEAD, 'target': HEAD}]})

    def test_worker_rejects_unrelated_target(self):
        for expected in ((8, HEAD, HEAD), (7, HEAD, MERGE), (True, HEAD, HEAD)):
            with self.subTest(expected=expected), self.assertRaises(mod.authority.AuthorityError):
                mod.run_checks(REPO, 1, BOT, 123, GitHub(), expected=expected)

    def test_obsolete_discovery_does_not_publish(self):
        post = mock.Mock()
        result = mod.run_checks(REPO, 1, BOT, 123, GitHub(), post, expected=(7, 'f' * 40, 'f' * 40))
        self.assertEqual(result['checks'][0]['status'], 'obsolete')
        post.assert_not_called()

    def test_review_edit_dismissal_and_head_races_do_not_publish(self):
        for change in ('dismiss', 'edit', 'head', 'close', 'queue'):
            with self.subTest(change=change):
                api, post = GitHub(), mock.Mock()
                if change == 'edit':
                    api.reviews[0].update(state='COMMENTED', body='/decider approve ' + HEAD)
                if change == 'queue':
                    api.collector.update(event='merge_group', head_branch='gh-readonly-queue/main/pr-7-abcdef0', head_sha=MERGE)
                def evaluate(*args):
                    if change == 'dismiss':
                        api.reviews[0]['state'] = 'DISMISSED'
                    elif change == 'edit':
                        api.reviews[0]['body'] = '/decider withdraw ' + HEAD
                    elif change == 'head':
                        api.pr['head']['sha'] = 'f' * 40
                    elif change == 'close':
                        api.pr['state'] = 'closed'
                    else:
                        api.queue_sha = HEAD
                    return {'status': 'authorized', 'head': HEAD}
                with mock.patch.object(mod, 'check_pr', side_effect=evaluate):
                    if change == 'queue':
                        with self.assertRaises(mod.authority.AuthorityError):
                            mod.run_checks(REPO, 1, BOT, 123, api, post)
                    else:
                        result = mod.run_checks(REPO, 1, BOT, 123, api, post)
                        self.assertEqual(result['checks'][0]['status'], 'obsolete')
                post.assert_not_called()

    def test_late_review_command_rechecks_without_poll_window(self):
        api = GitHub()
        api.collector.update(event='pull_request_review', created_at='2020-01-01T00:00:00Z')
        api.files = [{'filename': 'ci/policy.py', 'status': 'modified'}]
        api.reviews[0].update(state='COMMENTED', body='/decider approve ' + HEAD)
        post = mock.Mock(return_value={'app': {'id': 123}})
        self.assertEqual(mod.run_checks(REPO, 1, BOT, 123, api, post,
                                       expected=(7, HEAD, HEAD))['checks'][0]['status'], 'authorized')
        self.assertEqual(post.call_args.args[1]['conclusion'], 'success')
        api.reviews[0]['body'] = '/decider withdraw ' + HEAD
        mod.run_checks(REPO, 2, BOT, 123, api, post, expected=(7, HEAD, HEAD))
        self.assertEqual(post.call_args.args[1]['conclusion'], 'failure')

    def test_workflow_serializes_each_native_target_without_canceling_active_checks(self):
        text = (ROOT / '.github/workflows/decision-authority.yml').read_text()
        self.assertIn('group: authority-${{ github.repository_id }}-${{ matrix.number }}-${{ matrix.target }}', text)
        self.assertIn('cancel-in-progress: false', text)
        self.assertIn('ref: main', text)
        self.assertIn('--resolve-targets', text)
        self.assertNotIn('issue_comment:', text)

    def test_late_review_rechecks_current_queue_and_head(self):
        api = GitHub()
        api.collector['event'] = 'pull_request_review'
        api.queue_refs = [{'ref': 'refs/heads/gh-readonly-queue/main/pr-7-abcdef0',
                           'object': {'type': 'commit', 'sha': MERGE}}]
        matrix = mod.resolve_targets(REPO, 1, api)['include']
        self.assertEqual({row['target'] for row in matrix}, {HEAD, MERGE})
        api.files = [{'filename': 'ci/policy.py', 'status': 'modified'}]
        api.head_tree = api.queue_tree = {'truncated': False, 'tree': []}
        api.reviews = []
        post = mock.Mock(return_value={'app': {'id': 123}})
        mod.run_checks(REPO, 1, BOT, 123, api, post, expected=(7, HEAD, MERGE))
        self.assertEqual(post.call_count, 1)
        self.assertEqual(post.call_args.args[1]['head_sha'], MERGE)
        self.assertEqual(post.call_args.args[1]['conclusion'], 'failure')

    def test_untrusted_or_replaced_queue_ref_cannot_publish(self):
        api = GitHub()
        api.queue_refs = [{'ref': 'refs/heads/gh-readonly-queue/main/pr-8-abcdef0',
                           'object': {'type': 'commit', 'sha': MERGE}}]
        with self.assertRaises(mod.authority.AuthorityError):
            mod.resolve_targets(REPO, 1, api)
        api.queue_refs = [{'ref': 'refs/heads/gh-readonly-queue/main/pr-7-abcdef0',
                           'object': {'type': 'commit', 'sha': MERGE}}]
        post = mock.Mock()
        def replace(*args):
            api.queue_refs = []
            return {'status': 'authorized', 'head': HEAD}
        with mock.patch.object(mod, 'check_pr', side_effect=replace):
            with self.assertRaises(mod.authority.AuthorityError):
                mod.run_checks(REPO, 1, BOT, 123, api, post, expected=(7, HEAD, MERGE))
        post.assert_not_called()

    def test_snapshot_read_errors_publish_failure_not_stale_success(self):
        for reads in ([mod.authority.AuthorityError('Unavailable reviews')],
                      ['initial', mod.authority.AuthorityError('Unavailable reviews')]):
            with self.subTest(reads=reads):
                api = GitHub()
                api.files = [{'filename': 'ci/policy.py', 'status': 'modified'}]
                post = mock.Mock(return_value={'app': {'id': 123}})
                with mock.patch.object(mod, 'review_fingerprint', side_effect=reads):
                    mod.run_checks(REPO, 1, BOT, 123, api, post, expected=(7, HEAD, HEAD))
                self.assertEqual(post.call_args.args[1]['conclusion'], 'failure')

    def test_final_pr_read_failure_invalidates_pinned_target(self):
        api, post = GitHub(), mock.Mock(return_value={'app': {'id': 123}})
        def evaluate(*args):
            original = api.__class__.__call__
            def fail_latest(instance, endpoint):
                if endpoint == f'repos/{REPO}/pulls/7':
                    raise mod.authority.AuthorityError('PR revalidation unavailable')
                return original(instance, endpoint)
            patcher = mock.patch.object(api.__class__, '__call__', fail_latest)
            patcher.start()
            self.addCleanup(patcher.stop)
            return {'status': 'authorized', 'head': HEAD}
        with mock.patch.object(mod, 'check_pr', side_effect=evaluate):
            mod.run_checks(REPO, 1, BOT, 123, api, post, expected=(7, HEAD, HEAD))
        self.assertEqual(post.call_args.args[1]['conclusion'], 'failure')
        self.assertEqual(post.call_args.args[1]['head_sha'], HEAD)


if __name__ == '__main__':
    unittest.main()
