#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Dependency identity is not authority; only authenticated immutable pin changes qualify."""
import base64
from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci/decisions'))
import dependency_update as dependency

BASE, HEAD, MERGE_BASE = 'a' * 40, 'b' * 40, 'a' * 40
OLD, NEW, TAG = 'd' * 40, 'e' * 40, 'f' * 40
PATH = '.github/workflows/example.yml'
BEFORE = 'name: Test\non: push\njobs:\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@' + OLD + ' # v7.0.0\n      - run: echo safe\n'
AFTER = BEFORE.replace(OLD, NEW).replace('v7.0.0', 'v7.0.1')


class GitHub:
    def __init__(self, before=BEFORE, after=AFTER, path=PATH):
        repo = {'id': dependency.REPOSITORY_ID, 'full_name': dependency.REPOSITORY}
        self.pull = {'number': 7, 'state': 'open', 'draft': True, 'user': deepcopy(dependency.BOT),
                     'base': {'sha': BASE, 'ref': 'main', 'repo': deepcopy(repo)},
                     'head': {'sha': HEAD, 'ref': 'dependabot/actions', 'repo': deepcopy(repo)}, 'changed_files': 1}
        self.files = [{'filename': path, 'status': 'modified'}]
        self.blobs, self.trees = {}, {}
        for commit, text in ((MERGE_BASE, before), (HEAD, after)):
            raw = text.encode()
            sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            self.blobs[sha] = {'sha': sha, 'size': len(raw), 'encoding': 'base64', 'content': base64.b64encode(raw).decode()}
            self.trees[commit] = {'truncated': False, 'tree': [{'path': path, 'type': 'blob', 'mode': '100644', 'sha': sha}]}
        self.add_file('.github/workflows/ci.yml', 'permissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo safe\n')
        self.add_file('.github/workflows/decision-events.yml', (ROOT / '.github/workflows/decision-events.yml').read_text())
        self.ref = {'ref': 'refs/tags/v7.0.1', 'object': {'type': 'commit', 'sha': NEW}}
        self.tag = {'sha': TAG, 'object': {'type': 'commit', 'sha': NEW}}
        self.calls = []

    def add_file(self, path, before, after=None):
        for commit, text in ((MERGE_BASE, before), (HEAD, before if after is None else after)):
            raw = text.encode()
            sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            self.blobs[sha] = {'sha': sha, 'size': len(raw), 'encoding': 'base64', 'content': base64.b64encode(raw).decode()}
            self.trees[commit]['tree'] = [x for x in self.trees[commit]['tree'] if x['path'] != path]
            self.trees[commit]['tree'].append({'path': path, 'type': 'blob', 'mode': '100644', 'sha': sha})

    def __call__(self, endpoint):
        self.calls.append(endpoint)
        prefix = 'repos/' + dependency.REPOSITORY
        if endpoint == prefix + '/pulls/7': return deepcopy(self.pull)
        if endpoint.startswith(prefix + '/pulls/7/files?'): return deepcopy(self.files)
        if endpoint == prefix + f'/compare/{BASE}...{HEAD}':
            return {'base_commit': {'sha': BASE}, 'merge_base_commit': {'sha': MERGE_BASE}}
        if '/git/trees/' in endpoint:
            return deepcopy(self.trees.get(endpoint.split('/git/trees/')[1].split('?')[0], self.trees[MERGE_BASE]))
        if '/git/blobs/' in endpoint: return deepcopy(self.blobs[endpoint.rsplit('/', 1)[1]])
        if endpoint == 'repos/actions/checkout/git/ref/tags/v7.0.1': return deepcopy(self.ref)
        if endpoint == 'repos/actions/checkout/git/tags/' + TAG: return deepcopy(self.tag)
        raise AssertionError(endpoint)

    def inspect(self):
        return dependency.inspect(self, dependency.REPOSITORY, self.pull)

    def classify(self):
        return dependency.classify(self, self.inspect())


class Boundaries(unittest.TestCase):
    def test_exact_official_pin_change_and_annotated_tag(self):
        api = GitHub()
        self.assertEqual(api.classify(), [{'path': PATH, 'action': 'actions/checkout', 'old': OLD, 'new': NEW, 'version': 'v7.0.1'}])
        api.ref['object'] = {'type': 'tag', 'sha': TAG}
        self.assertEqual(len(api.classify()), 1)
        self.assertFalse(any('/commits/' in call for call in api.calls))

    def test_composite_and_existing_reusable_workflow_nodes(self):
        examples = [('.github/actions/test/action.yml', 'name: Test\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@'),
                    (PATH, 'name: Test\non: push\njobs:\n  test:\n    uses: actions/checkout@')]
        for path, prefix in examples:
            before = prefix + OLD + ' # v7.0.0\n'
            with self.subTest(path=path):
                self.assertEqual(len(GitHub(before, before.replace(OLD, NEW).replace('v7.0.0', 'v7.0.1'), path).classify()), 1)

    def test_identity_is_numeric_and_same_repository(self):
        mutations = [lambda p: p['user'].update(id=1), lambda p: p['user'].update(id=True),
                     lambda p: p['user'].update(type='User'), lambda p: p['user'].update(login='other[bot]'),
                     lambda p: p['head']['repo'].update(id=1), lambda p: p['base']['repo'].update(full_name='fork/finite'),
                     lambda p: p['base'].update(ref='other'), lambda p: p['head'].update(sha='main'),
                     lambda p: p.update(state='closed')]
        for mutate in mutations:
            api = GitHub(); mutate(api.pull)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): api.inspect()

    def test_shape_remains_stdlib_and_grants_no_authority(self):
        api = GitHub()
        with mock.patch.dict(sys.modules, {'yaml': None}):
            context = api.inspect()
        self.assertNotIn('approved', context)
        self.assertEqual(context['mergeBase'], MERGE_BASE)

    def test_incomplete_inventories_hidden_files_modes_and_truncated_trees(self):
        for kind in ('count', 'duplicate', 'rename', 'new', 'mode', 'symlink', 'hidden', 'truncated', 'otherfile'):
            api = GitHub()
            if kind == 'count': api.pull['changed_files'] = 2
            if kind == 'duplicate': api.files *= 2; api.pull['changed_files'] = 2
            if kind == 'rename': api.files[0].update(previous_filename='other.yml', status='renamed')
            if kind == 'new': api.trees[MERGE_BASE]['tree'] = []
            if kind == 'mode': api.trees[HEAD]['tree'][0]['mode'] = '100755'
            if kind == 'symlink': api.trees[HEAD]['tree'][0]['mode'] = '120000'
            if kind == 'hidden': api.trees[HEAD]['tree'].append({'path': 'secret', 'mode': '100644', 'type': 'blob', 'sha': TAG})
            if kind == 'truncated': api.trees[HEAD]['truncated'] = True
            if kind == 'otherfile': api.files[0]['filename'] = 'flake.lock'
            with self.subTest(kind=kind), self.assertRaises(ValueError): api.inspect()

    def test_blob_identity_size_and_encoding_are_authenticated(self):
        for update in ({'sha': TAG}, {'size': 1}, {'content': '!!!!'}, {'encoding': 'none'}):
            api = GitHub(); next(iter(api.blobs.values())).update(update)
            with self.subTest(update=update), self.assertRaises(ValueError): api.inspect()

    def test_every_other_workflow_change_is_rejected(self):
        mutations = [lambda s: s.replace('on: push', 'on: pull_request_target'),
                     lambda s: s.replace('echo safe', 'echo malicious'),
                     lambda s: s.replace('runs-on: ubuntu-24.04', 'runs-on: self-hosted'),
                     lambda s: s + 'permissions: write-all\n', lambda s: s + 'env:\n  TOKEN: value\n',
                     lambda s: s.replace('actions/checkout', 'attacker/checkout'),
                     lambda s: s.replace('actions/checkout@', 'actions/checkout/other@'),
                     lambda s: s.replace('      - run:', '        with:\n          token: value\n      - run:'),
                     lambda s: s.replace('steps:', 'steps:\n      - uses: actions/checkout@' + OLD + ' # v7.0.0')]
        for mutate in mutations:
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, AssertionError)):
                GitHub(after=mutate(AFTER)).classify()

    def test_yaml_ambiguity_and_run_scalar_lookalikes_are_rejected(self):
        prefixes = ['extra: &alias value\n', 'extra: !!str value\n', 'name: Duplicate\n',
                    'extra: {same: a, same: b}\n', 'extra: {<<: {a: b}}\n',
                    'extra: {1: a, 01: b}\n', 'extra: {true: a, True: b}\n']
        for prefix in prefixes:
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                GitHub(prefix + BEFORE, prefix + AFTER).classify()
        for suffix in ('---\nname: Other\n', '\n---\n'):
            with self.assertRaises(ValueError): GitHub(BEFORE + suffix, AFTER + suffix).classify()
        before = 'name: Test\njobs:\n  test:\n    steps:\n      - run: |\n          uses: actions/checkout@' + OLD + ' # v7.0.0\n'
        with self.assertRaises(ValueError):
            GitHub(before, before.replace(OLD, NEW).replace('v7.0.0', 'v7.0.1')).classify()

    def test_unsupported_comments_and_comment_only_changes_do_not_qualify(self):
        for value in ('main', 'v7.0.1 extra', 'https://attacker', 'v7.0.1\n# extra'):
            with self.subTest(value=value), self.assertRaises(ValueError): GitHub(after=AFTER.replace('v7.0.1', value)).classify()
        with self.assertRaises(ValueError): GitHub(after=BEFORE.replace('v7.0.0', 'v7.0.1')).classify()

    def test_missing_moved_fork_only_cyclic_and_wrong_type_tags_fail(self):
        for change in ('name', 'sha', 'cycle', 'type', 'wrongtag'):
            api = GitHub()
            if change == 'name': api.ref['ref'] = 'refs/tags/v7'
            if change == 'sha': api.ref['object']['sha'] = OLD
            if change == 'type': api.ref['object']['type'] = 'blob'
            if change in ('cycle', 'wrongtag'):
                api.ref['object'] = {'type': 'tag', 'sha': TAG}
                if change == 'cycle': api.tag['object'] = deepcopy(api.ref['object'])
                else: api.tag['sha'] = OLD
            with self.subTest(change=change), self.assertRaises(ValueError): api.classify()
        api = GitHub()
        def unavailable(endpoint):
            if '/git/ref/' in endpoint: raise RuntimeError('404 / fork-only commit')
            return api(endpoint)
        with self.assertRaises(RuntimeError): dependency.classify(unavailable, api.inspect())

    def test_final_head_base_and_author_are_revalidated(self):
        for side in ('head', 'base', 'user'):
            api = GitHub(); context = api.inspect()
            if side == 'user': api.pull['user']['id'] = 1
            else: api.pull[side]['sha'] = TAG
            with self.subTest(side=side), self.assertRaises(ValueError):
                dependency.revalidate(api, dependency.REPOSITORY, context)


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


authority_fixture = load('dependency_authority_fixture', 'tests/decisions/test_authority.py')
import ci_admission as admission
import json
POLICY = json.loads((ROOT / 'ci/ci-admission-policy.json').read_text())


class Integration(unittest.TestCase):
    def setUp(self):
        self.source = GitHub()
        self.humans = authority_fixture.GitHub()
        self.humans.reviews[0]['commit_id'] = HEAD
        self.review_reads = 0
        self.revoke_at = None
        self.posts = []
        self.mutate = lambda endpoint: None
        self.calls = []
        self.run = {'id': 40, 'run_attempt': 1, 'workflow_id': 50, 'path': '.github/workflows/ci.yml',
                    'repository': deepcopy(self.source.pull['base']['repo']),
                    'head_repository': deepcopy(self.source.pull['head']['repo']),
                    'head_sha': HEAD, 'head_branch': self.source.pull['head']['ref'], 'event': 'pull_request',
                    'status': 'completed', 'conclusion': 'action_required',
                    'actor': deepcopy(dependency.BOT), 'triggering_actor': deepcopy(dependency.BOT)}
        self.collector = {**deepcopy(self.run), 'id': 41, 'workflow_id': 51, 'event': 'pull_request_review',
                          'path': admission.COLLECTOR, 'conclusion': 'success'}
        self.recovery = {**deepcopy(self.run), 'id': 42, 'workflow_id': 52, 'path': admission.AUTHORITY,
                         'event': 'workflow_run', 'head_branch': 'main', 'head_sha': BASE, 'conclusion': 'success'}

    def api(self, endpoint):
        self.calls.append(endpoint)
        self.mutate(endpoint)
        if '/reviews?' in endpoint:
            self.review_reads += 1
            if self.revoke_at and self.review_reads >= self.revoke_at:
                self.humans.members = []
            return deepcopy(self.humans.reviews)
        if '/teams/' in endpoint or '/collaborators/' in endpoint:
            return self.humans(endpoint)
        if '/commits/' in endpoint:
            return [{'number': 7}]
        for run in (self.run, self.collector, self.recovery):
            if endpoint.endswith('/actions/runs/' + str(run['id'])): return deepcopy(run)
            if endpoint.endswith('/actions/workflows/' + str(run['workflow_id'])):
                return {'id': run['workflow_id'], 'path': run['path'], 'state': 'active'}
        if '/actions/runs?' in endpoint:
            return {'workflow_runs': [deepcopy(self.run)]}
        return self.source(endpoint)

    def admit(self):
        return admission.approve_run(self.api, self.posts.append, POLICY, self.run['id'])

    def test_official_current_head_has_one_admission_owner(self):
        self.assertEqual(self.admit(), 'approved')
        self.assertEqual(self.posts, [f'repos/{dependency.REPOSITORY}/actions/runs/40/approve'])
        self.assertEqual(self.review_reads, 0)
        self.assertEqual(sum('/git/trees/' in call for call in self.source.calls), 2)

    def test_execution_needs_no_review_but_merge_still_does(self):
        self.humans.reviews = []
        self.assertEqual(self.admit(), 'approved')
        self.assertEqual(self.review_reads, 0)
        from decision_authority import approval, HumanDecisionRequired
        with self.assertRaises(HumanDecisionRequired):
            approval(self.api, dependency.REPOSITORY, 7, HEAD)

    def test_impostor_or_untrusted_actor_cannot_use_dependency_exception(self):
        for field in ('author', 'actor', 'triggering_actor'):
            self.setUp()
            if field == 'author': self.source.pull['user']['id'] = 1
            else: self.run[field]['id'] = 1
            with self.subTest(field=field):
                self.assertNotEqual(self.admit(), 'approved')
                self.assertEqual(self.posts, [])

    def test_dependency_source_and_review_policy_cannot_be_weakened(self):
        self.run['head_repository']['full_name'] = 'attacker/fork'
        self.assertEqual(self.admit(), 'dependency-origin-mismatch')
        self.assertEqual(self.posts, [])
        self.setUp()
        policy = deepcopy(POLICY)
        policy['dependabot']['requiresCurrentHeadHumanMergeApproval'] = False
        with self.assertRaises(admission.AuthorityError):
            admission.approve_run(self.api, self.posts.append, policy, 40)
        self.assertEqual(self.posts, [])

    def test_changed_head_base_actor_and_attempt_fail_before_post(self):
        for field in ('head', 'base', 'actor', 'attempt'):
            self.setUp()
            def mutate(endpoint):
                if endpoint.endswith('/actions/runs/40') and self.calls.count(endpoint) == 2:
                    if field in ('head', 'base'): self.source.pull[field]['sha'] = TAG
                    elif field == 'actor': self.run['triggering_actor']['id'] = 1
                    else: self.run['run_attempt'] = 2
            self.mutate = mutate
            with self.subTest(field=field):
                try: self.assertNotEqual(self.admit(), 'approved')
                except ValueError: pass
                self.assertEqual(self.posts, [])

    def test_non_pin_and_native_lock_updates_stay_blocked_without_stalling_other_runs(self):
        self.source = GitHub(after=AFTER.replace('echo safe', 'echo injected'))
        with self.assertRaisesRegex(ValueError, 'outside immutable'): self.admit()
        self.assertEqual(self.posts, [])
        self.source = GitHub(path='flake.lock')
        self.source.pull['head']['ref'] = self.run['head_branch'] = 'dependabot/nix/nixpkgs-example'
        with self.assertRaises(ValueError): self.admit()
        self.assertEqual(self.posts, [])
        self.assertEqual(self.review_reads, 0)
        self.source = GitHub()
        self.run['head_branch'] = self.source.pull['head']['ref']
        self.assertEqual(self.admit(), 'approved')

    def test_incomplete_metadata_is_not_a_harmless_unsupported_family(self):
        for case in ('truncated', 'inventory', 'blob'):
            self.setUp()
            if case == 'truncated': self.source.trees[HEAD]['truncated'] = True
            if case == 'inventory': self.source.pull['changed_files'] = 2
            if case == 'blob': next(iter(self.source.blobs.values()))['size'] = 1
            with self.subTest(case=case), self.assertRaises(ValueError): self.admit()
            self.assertEqual(self.posts, [])

    def test_api_errors_and_uncertain_mutation_never_retry(self):
        def fail(endpoint):
            if '/git/trees/' in endpoint: raise admission.AuthorityError('read unavailable')
        self.mutate = fail
        with self.assertRaises(admission.AuthorityError): self.admit()
        self.assertEqual(self.posts, [])
        self.setUp()
        def lost(endpoint):
            self.posts.append(endpoint)
            raise TimeoutError('uncertain write')
        with self.assertRaises(TimeoutError):
            admission.approve_run(self.api, lost, POLICY, 40)
        self.assertEqual(len(self.posts), 1)

    def test_late_review_wakes_original_ci_without_granting_authority(self):
        self.humans.reviews = []
        self.assertEqual(admission.wake_runs(self.api, POLICY, 41), [40])
        self.assertTrue(any('head_sha=' + HEAD in call for call in self.calls))
        self.assertEqual(self.review_reads, 0)
        self.assertEqual(self.admit(), 'approved')
        self.assertEqual(len(self.posts), 1)
        self.collector['head_sha'] = BASE
        with self.assertRaises(admission.AuthorityError): admission.wake_runs(self.api, POLICY, 41)

    def test_blocked_review_collector_uses_same_live_dependency_predicate(self):
        self.run.update(event='pull_request_review', path=admission.COLLECTOR)
        self.assertEqual(admission.wake_runs(self.api, POLICY, 40), [40])
        self.assertEqual(self.admit(), 'approved')
        self.setUp(); self.run.update(event='pull_request_review', path='.github/workflows/codeql.yml')
        self.assertEqual(self.admit(), 'not-pending-ci')
        self.assertEqual(self.posts, [])

    def test_success_or_mixed_failure_authority_is_only_a_wakeup(self):
        self.humans.reviews = []
        for conclusion in ('success', 'failure'):
            self.recovery['conclusion'] = conclusion
            self.assertEqual(admission.wake_runs(self.api, POLICY, 42), [40])
        self.assertEqual(self.review_reads, 0)
        self.assertEqual(self.admit(), 'approved')
        self.assertEqual(len(self.posts), 1)
        for change in ({'head_branch': 'attacker'}, {'event': 'pull_request'}, {'conclusion': 'cancelled'},
                       {'conclusion': 'timed_out'}, {'repository': {'id': 1}}, {'head_repository': {'id': 1}}):
            previous = deepcopy(self.recovery); self.recovery.update(change)
            with self.subTest(change=change), self.assertRaises(admission.AuthorityError):
                admission.wake_runs(self.api, POLICY, 42)
            self.recovery = previous

    def test_positive_native_195_codeql_pin_fixture(self):
        fixture = ROOT / 'tests/fixtures/dependabot-195'
        for name, identity in [('before.yml', 'b80fa092dbf58a3cb8bf253d889cd27e8a776ea9'),
                               ('after.yml', 'f6e920ada34d8e7b5b85ba6f2df1739151b9c4a3')]:
            raw = (fixture / name).read_bytes()
            self.assertEqual(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), identity)
        self.source = GitHub((fixture / 'before.yml').read_text(), (fixture / 'after.yml').read_text(),
                             '.github/workflows/codeql.yml')
        def api(endpoint):
            if endpoint == 'repos/github/codeql-action/git/ref/tags/v4.39.1':
                return {'ref': 'refs/tags/v4.39.1', 'object': {'type': 'tag', 'sha': '8498dc4c2b27cdd99baf0f87955b29ebbf30c78d'}}
            if endpoint == 'repos/github/codeql-action/git/tags/8498dc4c2b27cdd99baf0f87955b29ebbf30c78d':
                return {'sha': '8498dc4c2b27cdd99baf0f87955b29ebbf30c78d',
                        'object': {'type': 'commit', 'sha': '9b3254085494b55a0f7c4c2b3d2d52cc712ce370'}}
            return self.api(endpoint)
        changes = dependency.classify(api, self.source.inspect())
        self.assertEqual([change['action'] for change in changes], ['github/codeql-action/init', 'github/codeql-action/analyze'])
        self.run['path'] = '.github/workflows/codeql.yml'
        with self.assertRaisesRegex(ValueError, 'read-only'):
            admission.approve_run(api, self.posts.append, POLICY, 40)
        self.assertEqual(self.posts, [])

    def test_workflow_tool_precedes_credentials_and_permissions_do_not_expand(self):
        import yaml
        workflow = yaml.safe_load((ROOT / '.github/workflows/ci-admission.yml').read_text())
        steps = workflow['jobs']['admit']['steps']
        prepared = next(i for i, value in enumerate(steps) if value.get('id') == 'admission-tool')
        first_secret = next(i for i, value in enumerate(steps) if 'secrets.' in str(value))
        self.assertLess(prepared, first_secret)
        self.assertIn('nix build .#ci-admission --no-link --print-out-paths', steps[prepared]['run'])
        self.assertEqual(steps[-1]['run'], '"$ADMISSION_TOOL/bin/xo-nixpkg-ci-admission"')
        token = next(value['with'] for value in steps if value.get('id') == 'admission')
        self.assertEqual({k: v for k, v in token.items() if k.startswith('permission-')},
                         {'permission-actions': 'write', 'permission-contents': 'read',
                          'permission-pull-requests': 'read', 'permission-members': 'read'})
        flake = (ROOT / 'flake.nix').read_text()
        packages = flake.split('      packages = forAllSystems (', 1)[1].split('      devShells =', 1)[0]
        self.assertIn('ci-admission = applications.ciAdmission;', packages)
        self.assertIn('(pkgs.python3.withPackages (p: [ p.pyyaml ]))', (ROOT / 'nix/applications.nix').read_text())
        self.assertIn('(python3.withPackages (p: [ p.pyyaml ]))', (ROOT / 'nix/security-fixtures.nix').read_text())


if __name__ == '__main__':
    unittest.main()


class AutomaticBoundaries(Integration):
    """Run against real workflow bytes as well as immutable hostile fixtures."""
    def real_workflow(self, name):
        self.run['path'] = '.github/workflows/' + name
        for path in (ROOT / '.github').rglob('*.yml'):
            self.source.add_file(str(path.relative_to(ROOT)), path.read_text())

    def test_real_ci_codeql_and_collector_admit_without_human_review(self):
        for workflow in ('ci.yml', 'codeql.yml', 'decision-events.yml', 'repository-secret-scan.yml'):
            self.setUp(); self.real_workflow(workflow); self.humans.reviews = []
            with self.subTest(workflow=workflow):
                self.assertEqual(self.admit(), 'approved')
                self.assertEqual(self.review_reads, 0)
                self.assertFalse(self.source.pull['draft'] is False)  # admission never changes metadata

    def test_write_oidc_secret_reusable_runner_and_skip_expression_fail_closed(self):
        safe = 'permissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo safe\n'
        mutations = [safe.replace('contents: read', 'contents: write'),
                     safe.replace('contents: read', 'id-token: write'),
                     safe.replace('echo safe', "echo ${{ secrets['KEY'] }}"),
                     safe.replace('echo safe', "echo ${{ toJSON(Secrets) }}"),
                     safe.replace('ubuntu-24.04', 'self-hosted'),
                     safe.replace('    steps:', '    uses: owner/repo/.github/workflows/run.yml@' + OLD + '\n    steps:'),
                     safe.replace('    runs-on:', '    permissions:\n      contents: write\n    runs-on:'),
                     safe.replace('    runs-on:', '    if: ' + dependency.NON_PR + " && false || true\n    permissions:\n      contents: write\n    runs-on:")]
        for text in mutations:
            self.setUp(); self.source.add_file('.github/workflows/ci.yml', text)
            with self.subTest(text=text), self.assertRaises(ValueError): self.admit()
            self.assertEqual(self.posts, [])

    def native(self, synchronized=True):
        import copy
        self.source.files = [{'filename': p, 'status': 'modified'} for p in ('flake.lock', 'devenv.lock')]
        if not synchronized:
            self.source.files = self.source.files[:1]
        self.source.pull['changed_files'] = len(self.source.files)
        self.source.pull['head']['ref'] = self.run['head_branch'] = 'dependabot/nix/nixpkgs-example'
        for revision in (MERGE_BASE, HEAD):
            self.source.trees[revision]['tree'] = [x for x in self.source.trees[revision]['tree'] if x['path'] != PATH]
        for name in ('flake.lock', 'devenv.lock'):
            old = json.loads((ROOT / name).read_text()); new = copy.deepcopy(old)
            node = new['nodes'][new['nodes']['root']['inputs']['nixpkgs']]['locked']
            node['rev'] = NEW
            node['lastModified'] += 1
            self.source.add_file(name, json.dumps(old), json.dumps(new if synchronized or name == 'flake.lock' else old))

    def test_complete_synchronized_nix_pair_admits_all_readonly_workflows(self):
        for workflow in ('ci.yml', 'codeql.yml', 'decision-events.yml', 'repository-secret-scan.yml'):
            self.setUp(); self.native(); self.real_workflow(workflow); self.humans.reviews = []
            with self.subTest(workflow=workflow):
                self.assertEqual(self.admit(), 'approved')
                self.assertEqual(self.review_reads, 0)

    def test_unpaired_nix_waits_and_hidden_delta_or_unsafe_workflow_never_admit(self):
        self.native(synchronized=False)
        self.assertEqual(self.admit(), 'unsupported-dependency-family')
        self.assertEqual(self.posts, [])
        for kind in ('controller', 'unrelated-lock', 'symlink', 'foreign', 'partial'):
            self.setUp(); self.native()
            if kind == 'controller':
                self.source.add_file('ci/malicious.py', 'safe', 'unsafe')
            if kind == 'unrelated-lock':
                entry = next(x for x in self.source.trees[HEAD]['tree'] if x['path'] == 'flake.lock')
                value = json.loads(base64.b64decode(self.source.blobs[entry['sha']]['content']))
                value['nodes']['root']['inputs']['extra'] = 'evil'
                before_entry = next(x for x in self.source.trees[MERGE_BASE]['tree'] if x['path'] == 'flake.lock')
                before = base64.b64decode(self.source.blobs[before_entry['sha']]['content']).decode()
                self.source.add_file('flake.lock', before, json.dumps(value))
            if kind == 'symlink': self.source.trees[HEAD]['tree'][-1]['mode'] = '120000'
            if kind == 'foreign': self.source.pull['head']['repo']['id'] = 1
            if kind == 'partial': self.source.pull['changed_files'] = 1
            with self.subTest(kind=kind):
                try: self.assertNotEqual(self.admit(), 'approved')
                except (ValueError, admission.AuthorityError): pass
            self.assertEqual(self.posts, [])

    def test_diverged_main_only_privileged_source_cannot_borrow_head_audit(self):
        # The native pull_request run executes a synthetic merge, not headTree.
        # Main-only changes must not be omitted from the execution audit.
        for path, content in [('.github/workflows/ci.yml', 'permissions: {contents: write}'),
                              ('.github/actions/setup-nix/action.yml', 'secret credentialed action'),
                              ('.gitleaks.toml', 'different scanner configuration')]:
            self.setUp()
            self.source.pull['base']['sha'] = TAG
            raw = content.encode()
            mutation_sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            self.source.blobs[mutation_sha] = {'sha': mutation_sha, 'size': len(raw), 'encoding': 'base64',
                                               'content': base64.b64encode(raw).decode()}
            original = self.api
            def diverged(endpoint):
                if endpoint.endswith('/compare/' + TAG + '...' + HEAD):
                    return {'base_commit': {'sha': TAG}, 'merge_base_commit': {'sha': BASE}}
                if endpoint.endswith('/git/trees/' + TAG + '?recursive=1'):
                    return {'truncated': False, 'tree': [{'path': path, 'mode': '100644',
                            'type': 'blob', 'sha': mutation_sha}]}
                return original(endpoint)
            with self.subTest(path=path):
                self.assertEqual(admission.approve_run(diverged, self.posts.append, POLICY, 40),
                                 'unsupported-dependency-family')
                self.assertEqual(self.posts, [])
                self.assertFalse(any('/git/blobs/' in value for value in self.source.calls))

    def test_pr_cannot_export_or_attest_or_repair_hashes(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertNotIn('  fix-hashes:', workflow)
        self.assertIn('if: ' + dependency.NON_PR + " && needs.validate.outputs.cache_eligible == 'true'", workflow)
        export_lines = [line for line in workflow.splitlines() if 'XO_NIXPKG_EXPORT_REUSE_PAYLOAD:' in line]
        self.assertEqual(len(export_lines), 2)
        self.assertTrue(all("github.event_name != 'pull_request' &&" in line for line in export_lines))
