#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise cache provenance and isolation without network or Nix credentials."""
import copy
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('build_reuse', ROOT / 'ci/build-reuse.py')
reuse = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reuse)

SOURCE, CONTROLLER, TREE, MAIN = ('a' * 40, 'b' * 40, 'c' * 40, 'd' * 40)
OUTPUT = '/nix/store/' + '1' * 32 + '-xen-orchestra-6.9.1'
DERIVATION = '/nix/store/' + '2' * 32 + '-xen-orchestra-6.9.1.drv'
NAR_HASH = 'sha256-' + 'A' * 43 + '='
CACHE_POLICY = {'schema': 1, 'name': 'fixture', 'url': 'https://fixture.cachix.org',
                'publicKey': 'fixture.cachix.org-1:' + base64.b64encode(b'P' * 32).decode()}


class ReuseFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.controller = self.directory / 'controller'
        workflow = self.controller / reuse.WORKFLOW
        workflow.parent.mkdir(parents=True)
        workflow.write_text('trusted immutable controller workflow\n')
        self.receipt = {
            'schema': 2, 'repository': reuse.REPOSITORY, 'tree': TREE,
            'repositorySecretPolicy': {'policyId': 'gitleaks-incoming-native-publication-v2', 'policySha256': 'f' * 64},
            'system': 'x86_64-linux', 'source': SOURCE, 'controller': CONTROLLER,
            'runId': 101, 'runAttempt': 2, 'workflow': reuse.WORKFLOW,
            'event': 'pull_request', 'ref': 'refs/pull/97/merge',
            'workflowSha256': reuse.digest(workflow),
            'launcherSha256': reuse.digest(Path(reuse.__file__)),
            'outputs': {'xo-latest': {
                'attribute': 'packages.x86_64-linux.latest',
                'storePath': OUTPUT, 'derivation': DERIVATION, 'narHash': NAR_HASH}},
            'transport': {'fixture': 'authenticated transport manifest'},
            'authorityClaim': False,
        }
        self.run = {
            'id': 101, 'run_attempt': 2, 'status': 'completed', 'conclusion': 'success',
            'repository': {'full_name': reuse.REPOSITORY},
            'head_repository': {'full_name': reuse.REPOSITORY},
            'event': 'pull_request', 'path': reuse.WORKFLOW, 'head_sha': 'e' * 40,
            'pull_requests': [{
                'base': {'ref': 'main', 'sha': CONTROLLER,
                         'repo': {'url': f'https://api.github.com/repos/{reuse.REPOSITORY}'}},
                'head': {'sha': 'e' * 40,
                         'repo': {'url': f'https://api.github.com/repos/{reuse.REPOSITORY}'}},
            }],
        }
        self.commit = {'sha': SOURCE, 'tree': {'sha': TREE},
                       'parents': [{'sha': CONTROLLER}, {'sha': 'e' * 40}]}
        self.ancestry = {'status': 'ahead'}
        self.artifacts = [{'name': 'xo-ci-reuse-receipt-101-2', 'expired': False,
                           'size_in_bytes': 2000}]
        self.runs = [self.run]
        self.addCleanup(patch.stopall)
        patch.object(reuse, 'repository_policy_binding', return_value=copy.deepcopy(self.receipt['repositorySecretPolicy'])).start()
        patch.object(reuse, 'trusted_cache_policy', return_value=copy.deepcopy(CACHE_POLICY)).start()

    def api(self, path):
        prefix = 'repos/' + reuse.REPOSITORY
        if path == prefix + '/actions/runs/101/attempts/2':
            return copy.deepcopy(self.run)
        if path == prefix + '/git/commits/' + self.receipt['source']:
            return copy.deepcopy(self.commit)
        if path == prefix + '/git/ref/heads/main':
            return {'object': {'sha': MAIN}}
        if path == prefix + '/compare/' + self.receipt['controller'] + '...' + MAIN:
            return copy.deepcopy(self.ancestry)
        if path == prefix + '/actions/workflows/ci.yml/runs?status=success&per_page=30':
            return {'workflow_runs': copy.deepcopy(self.runs)}
        if path == prefix + '/actions/runs/101/artifacts':
            return {'artifacts': copy.deepcopy(self.artifacts)}
        raise AssertionError('Unexpected API query: ' + path)

    def blob(self, repository, revision, path):
        self.assertEqual(repository, reuse.REPOSITORY)
        self.assertIn(revision, (SOURCE, CONTROLLER))
        return self.receipt['workflowSha256'] if path == reuse.WORKFLOW else self.receipt['launcherSha256']

    def provenance_mocks(self):
        patch.object(reuse, 'api', side_effect=self.api).start()
        patch.object(reuse, 'blob', side_effect=self.blob).start()


class ProducerTests(ReuseFixture):
    def test_provenance_accepts_only_completed_protected_controller(self):
        self.provenance_mocks()
        self.assertEqual(reuse.producer(self.receipt, self.controller, TREE), self.run)

    def test_receipt_source_and_platform_substitutions_rejected(self):
        self.provenance_mocks()
        for key, value in [('schema', 1), ('repository', 'attacker/xo-nixpkg'),
                           ('tree', 'e' * 40), ('system', 'aarch64-linux'),
                           ('source', 'refs/heads/main'), ('controller', '../main'),
                           ('runId', True), ('runAttempt', 0),
                           ('workflow', '.github/workflows/release.yml'), ('event', 'push'),
                           ('ref', 'refs/heads/attacker')]:
            with self.subTest(key=key):
                receipt = dict(self.receipt, **{key: value})
                with self.assertRaises(ValueError):
                    reuse.producer(receipt, self.controller, TREE)

    def test_policy_binding_shape_is_validated_before_provenance(self):
        self.provenance_mocks()
        for binding in [None, {}, {'policyId': 'old-policy'},
                        {'policyId': 'old-policy', 'policySha256': 'bad'},
                        {'policyId': '../old-policy', 'policySha256': '0' * 64},
                        {'policyId': 'old-policy', 'policySha256': '0' * 64, 'extra': True}]:
            changed = dict(self.receipt, repositorySecretPolicy=binding)
            with self.assertRaisesRegex(ValueError, 'Invalid reuse policy binding'):
                reuse.producer(changed, self.controller, TREE)

    def test_old_policy_requires_provenance_and_is_never_compatible(self):
        self.provenance_mocks()
        changed = dict(self.receipt, repositorySecretPolicy={
            'policyId': 'github-native-secret-observation-v1', 'policySha256': '0' * 64})
        self.assertEqual(reuse.producer(changed, self.controller, TREE), self.run)
        with self.assertRaises(reuse.UnavailableProducer):
            reuse.compatible_producer(changed, self.controller)

    def test_api_run_attempt_event_fork_and_workflow_substitutions_rejected(self):
        self.provenance_mocks()
        original = copy.deepcopy(self.run)
        for key, value in [('id', 102), ('run_attempt', 1), ('status', 'in_progress'),
                           ('conclusion', 'failure'), ('event', 'merge_group'),
                           ('repository', {'full_name': 'attacker/repo'}),
                           ('head_repository', {'full_name': 'attacker/xo-nixpkg'}),
                           ('path', '.github/workflows/other.yml'), ('head_sha', 'f' * 40)]:
            with self.subTest(key=key):
                self.run = dict(original, **{key: value})
                with self.assertRaises(ValueError):
                    reuse.producer(self.receipt, self.controller, TREE)
        self.run = original

    def test_commit_tree_and_controller_ancestry_cannot_be_self_asserted(self):
        self.provenance_mocks()
        original = copy.deepcopy(self.commit)
        for change in [{'sha': 'e' * 40}, {'tree': {'sha': 'e' * 40}}]:
            self.commit = dict(original, **change)
            with self.assertRaises(ValueError): reuse.producer(self.receipt, self.controller, TREE)
        self.commit = original
        for status in ('behind', 'diverged'):
            self.ancestry = {'status': status}
            with self.assertRaises(ValueError): reuse.producer(self.receipt, self.controller, TREE)

    def test_pr_merge_commit_can_bind_real_head_parent_but_not_unrelated_sha(self):
        self.provenance_mocks()
        self.commit['parents'] = [{'sha': CONTROLLER}, {'sha': 'e' * 40}]
        self.run['head_sha'] = 'e' * 40
        reuse.producer(self.receipt, self.controller, TREE)
        self.run['head_sha'] = 'f' * 40
        with self.assertRaises(ValueError): reuse.producer(self.receipt, self.controller, TREE)

    def test_pr_controller_must_be_actual_protected_base_not_an_ancestor_claim(self):
        self.provenance_mocks()
        original = copy.deepcopy(self.run['pull_requests'])
        for side, key, value in [('base', 'ref', 'attacker-unprotected-branch'),
                                  ('base', 'sha', 'f' * 40),
                                  ('base', 'repo', {'url': 'https://api.github.com/repos/attacker/repo'}),
                                  ('head', 'repo', {'url': 'https://api.github.com/repos/attacker/repo'}),
                                  ('head', 'sha', 'f' * 40)]:
            with self.subTest(side=side, key=key):
                self.run['pull_requests'] = copy.deepcopy(original)
                self.run['pull_requests'][0][side][key] = value
                with self.assertRaisesRegex(ValueError, 'actual protected base'):
                    reuse.producer(self.receipt, self.controller, TREE)
        for pulls in ([], original * 2):
            self.run['pull_requests'] = pulls
            with self.assertRaisesRegex(ValueError, 'one protected-base PR'):
                reuse.producer(self.receipt, self.controller, TREE)
        self.run['pull_requests'] = original
        self.commit['parents'].reverse()
        with self.assertRaisesRegex(ValueError, 'actual protected base'):
            reuse.producer(self.receipt, self.controller, TREE)

    def test_queue_controller_bound_to_exact_queue_ref_and_first_parent(self):
        self.provenance_mocks()
        ref = 'refs/heads/gh-readonly-queue/main/pr-97-' + CONTROLLER
        self.receipt.update(event='merge_group', ref=ref)
        self.run.update(event='merge_group', head_sha=SOURCE, head_branch=ref.removeprefix('refs/heads/'))
        reuse.producer(self.receipt, self.controller, TREE)
        self.run['head_branch'] = 'gh-readonly-queue/main/pr-98-' + CONTROLLER
        with self.assertRaisesRegex(ValueError, 'exact base'): reuse.producer(self.receipt, self.controller, TREE)
        self.run['head_branch'] = ref.removeprefix('refs/heads/')
        self.commit['parents'][0]['sha'] = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'exact base'): reuse.producer(self.receipt, self.controller, TREE)

    def test_dispatch_requires_exact_main_source_as_controller(self):
        self.provenance_mocks()
        self.receipt.update(event='workflow_dispatch', ref='refs/heads/main', controller=SOURCE)
        self.run.update(event='workflow_dispatch', head_sha=SOURCE, head_branch='main')
        reuse.producer(self.receipt, self.controller, TREE)
        self.run['head_branch'] = 'attacker'
        with self.assertRaisesRegex(ValueError, 'exact main'): reuse.producer(self.receipt, self.controller, TREE)
        self.run['head_branch'] = 'main'
        self.receipt['controller'] = CONTROLLER
        with self.assertRaisesRegex(ValueError, 'exact main'): reuse.producer(self.receipt, self.controller, TREE)

    def test_workflow_and_launcher_bytes_must_match_independent_protected_source(self):
        patch.object(reuse, 'api', side_effect=self.api).start()
        for revision, path in [(SOURCE, reuse.WORKFLOW), (CONTROLLER, reuse.WORKFLOW),
                               (CONTROLLER, 'ci/build-reuse.py')]:
            with self.subTest(revision=revision, path=path):
                def modified(repository, queried_revision, queried_path):
                    if (queried_revision, queried_path) == (revision, path): return '0' * 64
                    return self.blob(repository, queried_revision, queried_path)
                with patch.object(reuse, 'blob', side_effect=modified):
                    with self.assertRaises(ValueError): reuse.producer(self.receipt, self.controller, TREE)
        for key in ('workflowSha256', 'launcherSha256'):
            receipt = dict(self.receipt, **{key: '0' * 64})
            with patch.object(reuse, 'blob', side_effect=self.blob):
                with self.assertRaises(ValueError): reuse.producer(receipt, self.controller, TREE)


class TrustedCachePolicyTests(unittest.TestCase):
    def test_policy_requires_exact_versioned_schema(self):
        self.assertEqual(reuse.validate_trusted_cache_policy(CACHE_POLICY), CACHE_POLICY)
        variants = [None, [], {}, dict(CACHE_POLICY, schema=True), dict(CACHE_POLICY, schema=2),
                    dict(CACHE_POLICY, pluginFiles='/tmp/evil.so')]
        variants += [{key: value for key, value in CACHE_POLICY.items() if key != field}
                     for field in CACHE_POLICY]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                reuse.validate_trusted_cache_policy(value)

    def test_policy_rejects_cache_config_injection_and_mismatched_https_hosts(self):
        values = {'name': ['', '-fixture', 'fixture-', 'fixture\nrequire-sigs = false', None],
                  'url': ['http://fixture.cachix.org', 'https://attacker.invalid',
                          'https://fixture.cachix.org/path', 'https://fixture.cachix.org?x=1',
                          'https://fixture.cachix.org#fragment', 'https://fixture.cachix.org:443',
                          'https://fixture.cachix.org@attacker.invalid',
                          'https://fixture.cachix.org\nplugin-files = /tmp/evil.so', None],
                  'publicKey': ['attacker.invalid-1:' + base64.b64encode(b'P' * 32).decode(),
                                CACHE_POLICY['publicKey'] + '\nrequire-sigs = false',
                                'fixture.cachix.org-1:' + base64.b64encode(b'P' * 31).decode(),
                                'fixture.cachix.org-1:' + base64.b64encode(b'P' * 33).decode(),
                                CACHE_POLICY['publicKey'][:-2] + 'B=', None]}
        for field, variants in values.items():
            for value in variants:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    reuse.validate_trusted_cache_policy(dict(CACHE_POLICY, **{field: value}))

    def test_policy_requires_bounded_regular_pinned_store_file(self):
        for path in ('', '/tmp/candidate/cache.json', '/nix/store/../cache.json',
                     '/nix/store/' + '1' * 32 + '-cache.json/extra'):
            with self.subTest(path=path), patch.dict(os.environ, {'XO_NIXPKG_TRUSTED_CACHE_POLICY': path}), \
                 self.assertRaisesRegex(ValueError, 'Pinned trusted cache policy required'):
                reuse.trusted_cache_policy()
        source = '/nix/store/' + '1' * 32 + '-cache.json'
        with patch.dict(os.environ, {'XO_NIXPKG_TRUSTED_CACHE_POLICY': source}), \
             patch.object(reuse, 'Path') as path:
            file = path.return_value
            file.is_symlink.return_value = False
            file.is_file.return_value = True
            file.stat.return_value.st_size = 200
            file.read_text.return_value = json.dumps(CACHE_POLICY)
            self.assertEqual(reuse.trusted_cache_policy(), CACHE_POLICY)
            for changes in ({'is_symlink': True}, {'is_file': False}, {'size': 4097}):
                file.is_symlink.return_value = changes.get('is_symlink', False)
                file.is_file.return_value = changes.get('is_file', True)
                file.stat.return_value.st_size = changes.get('size', 200)
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    reuse.trusted_cache_policy()


class IsolationAndPlanTests(ReuseFixture):
    def test_disabled_artifact_reuse_still_builds_every_selected_phase(self):
        candidate = self.directory / 'candidate'
        candidate.mkdir()
        (self.controller / 'ci').mkdir(exist_ok=True)
        (self.controller / 'ci/classifier.json').write_text(json.dumps({'preflightTargets': ['policy']}))
        targets = [{'name': 'policy', 'attribute': 'checks.x86_64-linux.policy'},
                   {'name': 'xo-latest', 'attribute': 'checks.x86_64-linux.xo-latest'}]
        plan = {'schemaVersion': 2, 'name': 'selected', 'targets': targets}
        environment = {'PATH': '/trusted/bin', 'GH_TOKEN': 'read-only-fixture',
                       'XO_NIXPKG_REUSE_BUILDS': 'false',
                       'PREPARED_CI_WORKFLOW': json.dumps({'jobs': {'validate': {'plan': plan}}}),
                       'XO_NIXPKG_TRUSTED_PLAN_NIX': '/nix/store/' + '4' * 32 + '-candidate-nix/bin/xo-nixpkg-candidate-nix',
                       'XO_NIXPKG_PLAN_RUNNER': '/nix/store/trusted-plan-runner/bin/runner'}
        built = []
        def build(args, **kwargs):
            built.extend(json.loads(Path(args[args.index('--plan-file') + 1]).read_text())['targets'])
            self.assertNotIn('GH_TOKEN', kwargs['env'])
        with patch.dict(os.environ, environment, clear=True), \
             patch.object(reuse, 'nix', return_value='') as native, \
             patch.object(reuse, 'api') as discovery, \
             patch.object(reuse.subprocess, 'run', side_effect=build):
            reuse.validate(candidate, self.controller, self.directory / 'evidence')
        self.assertEqual(built, targets)
        discovery.assert_not_called()
        self.assertEqual(native.call_count, 1)
        self.assertEqual(native.call_args.args[1:4], ('flake', 'check', '--no-build'))
        receipt = json.loads((self.directory / 'evidence/reuse-restore.json').read_text())
        self.assertEqual(receipt['status'], 'miss')
        self.assertFalse(receipt['authorityClaim'])

    def test_native_child_has_no_inherited_credentials_or_user_nix_configuration(self):
        poison = {'GH_TOKEN': 'secret', 'GITHUB_TOKEN': 'secret', 'AWS_SECRET_ACCESS_KEY': 'secret',
                  'CACHIX_AUTH_TOKEN': 'secret', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'secret',
                  'NIX_REMOTE': 'ssh://attacker',
                  'NIX_CONFIG': 'plugin-files = /tmp/evil.so\nrequire-sigs = false\n'
                                'extra-substituters = https://attacker.invalid\naccept-flake-config = true',
                  'NIX_CONF_DIR': '/tmp/candidate-config',
                  'NIX_USER_CONF_FILES': '/tmp/evil.conf', 'GIT_CONFIG_GLOBAL': '/tmp/evil',
                  'HOME': '/tmp/credential-home', 'BASH_ENV': '/tmp/evil.sh',
                  'LD_PRELOAD': '/tmp/evil.so', 'PYTHONPATH': '/tmp/evil', 'PATH': '/trusted/bin'}
        with patch.dict(os.environ, poison, clear=True):
            environment = reuse.child_environment(self.directory / 'native')
        for key in poison.keys() - {'PATH', 'HOME', 'NIX_CONFIG', 'NIX_CONF_DIR',
                                    'NIX_USER_CONF_FILES', 'GIT_CONFIG_GLOBAL'}:
            self.assertNotIn(key, environment)
        self.assertEqual(environment['PATH'], '/trusted/bin')
        self.assertEqual(environment['NIX_USER_CONF_FILES'], '/dev/null')
        self.assertEqual(environment['GIT_CONFIG_GLOBAL'], '/dev/null')
        self.assertIn('sandbox = true', environment['NIX_CONFIG'])
        self.assertIn('accept-flake-config = false', environment['NIX_CONFIG'])
        self.assertIn('require-sigs = true', environment['NIX_CONFIG'])
        self.assertIn('extra-substituters = ' + CACHE_POLICY['url'], environment['NIX_CONFIG'])
        self.assertIn('extra-trusted-public-keys = ' + CACHE_POLICY['publicKey'], environment['NIX_CONFIG'])
        self.assertNotIn('attacker', environment['NIX_CONFIG'])
        self.assertNotIn('plugin-files', environment['NIX_CONFIG'])
        self.assertNotIn('XO_NIXPKG_TRUSTED_CACHE_POLICY', environment)
        self.assertEqual((Path(environment['NIX_CONF_DIR']) / 'nix.conf').read_text(), '')

    def test_pinned_nix_cannot_use_candidate_nixconfig_or_remote_builders(self):
        with patch.dict(os.environ, {'XO_NIXPKG_TRUSTED_NIX': '/nix/store/' + '3' * 32 + '-nix/bin/nix'}):
            args = reuse.nix_arguments('eval', '--json', 'git+file:///candidate#package')
        self.assertIn('--no-accept-flake-config', args)
        for option, value in [('sandbox', 'true'), ('builders', ''), ('pure-eval', 'true'),
                               ('allow-unsafe-native-code-during-evaluation', 'false')]:
            self.assertTrue(any(args[index:index+3] == ['--option', option, value]
                                for index in range(len(args)-2)))
        with patch.dict(os.environ, {'XO_NIXPKG_TRUSTED_NIX': '/tmp/candidate/nix'}):
            with self.assertRaises(ValueError): reuse.nix_arguments('build')

    def test_plan_rejects_shell_attributes_duplicate_targets_and_extra_authority(self):
        valid = {'schemaVersion': 2, 'name': 'runtime', 'targets': [
            {'name': 'xo-latest', 'attribute': 'checks.x86_64-linux.xo-latest'}]}
        reuse.validate_plan(valid)
        invalid = [dict(valid, schemaVersion=1), dict(valid, targets=[]), dict(valid, trusted=True),
                   dict(valid, targets=valid['targets'] * 2)]
        for field, value in [('name', 'xo; touch /tmp/pwned'),
                              ('attribute', 'checks.x86_64-linux.foo;echo-pwned'),
                              ('attribute', 'checks.x86_64-linux.../evil'),
                              ('attribute', 'packages.x86_64-linux.latest')]:
            invalid.append(dict(valid, targets=[dict(valid['targets'][0], **{field: value})]))
        for plan in invalid:
            with self.subTest(plan=plan), self.assertRaises(ValueError): reuse.validate_plan(plan)

    def test_validation_calls_only_trusted_runner_with_candidate_as_flake_data(self):
        candidate = self.directory / 'candidate'
        candidate.mkdir()
        for name in ('devenv.nix', 'ci/run.sh', '.envrc'):
            path = candidate / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('touch /tmp/should-never-execute\n')
        (self.controller / 'ci').mkdir(exist_ok=True)
        (self.controller / 'ci/classifier.json').write_text(json.dumps({'preflightTargets': ['policy']}))
        plan = {'schemaVersion': 2, 'name': 'selected', 'targets': [
            {'name': 'policy', 'attribute': 'checks.x86_64-linux.policy'},
            {'name': 'xo-latest', 'attribute': 'checks.x86_64-linux.xo-latest'}]}
        environment = {'PATH': '/trusted/bin', 'GH_TOKEN': 'not-for-candidate',
                       'PREPARED_CI_WORKFLOW': json.dumps({'jobs': {'validate': {'plan': plan}}}),
                       'XO_NIXPKG_TRUSTED_NIX': '/nix/store/' + '3' * 32 + '-nix/bin/nix',
                       'XO_NIXPKG_TRUSTED_PLAN_NIX': '/nix/store/' + '4' * 32 + '-candidate-nix/bin/xo-nixpkg-candidate-nix',
                       'XO_NIXPKG_PLAN_RUNNER': '/nix/store/trusted-plan-runner/bin/runner'}
        with patch.dict(os.environ, environment, clear=True), \
             patch.object(reuse, 'nix', return_value='') as native, \
             patch.object(reuse, 'restore', return_value={'status': 'miss'}) as restore, \
             patch.object(reuse.subprocess, 'run') as runner:
            reuse.validate(candidate, self.controller, self.directory / 'evidence')
        self.assertEqual(runner.call_count, 2)
        for call in runner.call_args_list:
            self.assertEqual(call.args[0][0], environment['XO_NIXPKG_PLAN_RUNNER'])
            self.assertIn('git+file://' + str(candidate), call.args[0])
            self.assertNotIn('GH_TOKEN', call.kwargs['env'])
            self.assertNotIn('BASH_ENV', call.kwargs['env'])
            self.assertIn('extra-substituters = ' + CACHE_POLICY['url'], call.kwargs['env']['NIX_CONFIG'])
            self.assertEqual(call.kwargs['env']['FLAKE_PLAN_RUNNER_NIX'],
                             environment['XO_NIXPKG_TRUSTED_PLAN_NIX'])
            self.assertTrue(call.kwargs['check'])
        self.assertEqual(native.call_args.args[1:4], ('flake', 'check', '--no-build'))
        restore.assert_called_once()

    def test_validation_rejects_candidate_or_nonpackaged_plan_nix_wrapper(self):
        plan = {'schemaVersion': 2, 'name': 'selected', 'targets': [
            {'name': 'xo-latest', 'attribute': 'checks.x86_64-linux.xo-latest'}]}
        environment = {'PREPARED_CI_WORKFLOW': json.dumps({'jobs': {'validate': {'plan': plan}}})}
        for wrapper in ('/tmp/candidate/bin/xo-nixpkg-candidate-nix',
                        '/usr/bin/xo-nixpkg-candidate-nix',
                        '/nix/store/' + '4' * 32 + '-candidate-nix/bin/nix'):
            with self.subTest(wrapper=wrapper), \
                 patch.dict(os.environ, dict(environment, XO_NIXPKG_TRUSTED_PLAN_NIX=wrapper), clear=True), \
                 patch.object(reuse, 'nix') as native, \
                 patch.object(reuse.subprocess, 'run') as runner:
                with self.assertRaises(ValueError):
                    reuse.validate(self.directory / 'candidate', self.controller,
                                   self.directory / 'evidence')
                native.assert_not_called()
                runner.assert_not_called()


class AttestationTests(ReuseFixture):
    def test_verified_statement_must_bind_exact_attempt_and_source(self):
        invocation = f'https://github.com/{reuse.REPOSITORY}/actions/runs/101/attempts/2'
        statement = [{'verificationResult': {'statement': {'predicate': {
            'runDetails': {'metadata': {'invocationId': invocation}}}}}}]
        with patch.object(reuse, 'command', return_value=json.dumps(statement)) as command:
            reuse.verify_attestation(self.directory / 'receipt.json', self.receipt)
        args = command.call_args.args[0]
        for flag, value in [('--source-digest', SOURCE), ('--source-ref', 'refs/pull/97/merge'),
                            ('--signer-workflow', reuse.REPOSITORY + '/' + reuse.WORKFLOW)]:
            self.assertEqual(args[args.index(flag)+1], value)
        self.assertIn('--deny-self-hosted-runners', args)
        for wrong in (invocation.replace('attempts/2', 'attempts/1'),
                      invocation.replace('/runs/101/', '/runs/102/'),
                      invocation.replace(reuse.REPOSITORY, 'attacker/repo')):
            statement[0]['verificationResult']['statement']['predicate']['runDetails']['metadata']['invocationId'] = wrong
            with patch.object(reuse, 'command', return_value=json.dumps(statement)):
                with self.assertRaises(ValueError): reuse.verify_attestation(self.directory / 'receipt.json', self.receipt)

    def test_invalid_signature_is_hard_failure_not_cache_miss(self):
        with patch.object(reuse, 'command', side_effect=subprocess.CalledProcessError(1, ['gh', 'attestation'])):
            with self.assertRaisesRegex(ValueError, 'attestation verification failed'):
                reuse.verify_attestation(self.directory / 'receipt.json', self.receipt)


class RestoreTests(ReuseFixture):
    def setUp(self):
        super().setUp()
        self.provenance_mocks()
        patch.dict(os.environ, {'GH_TOKEN': 'read-only-fixture'}).start()
        patch.object(reuse, 'git', return_value=TREE).start()
        self.evaluated = {key: value for key, value in self.receipt['outputs']['xo-latest'].items()
                          if key != 'narHash'}
        patch.object(reuse, 'identity', side_effect=lambda *_: copy.deepcopy(self.evaluated)).start()
        self.native = patch.object(reuse, 'nix', return_value='').start()
        self.attestation = patch.object(reuse, 'verify_attestation').start()
        self.transport = Mock()
        patch.object(reuse, 'transport', return_value=self.transport).start()
        self.download = patch.object(reuse, 'command', side_effect=self.command).start()

    def command(self, args, **_kwargs):
        self.assertEqual(args[:3], ['gh', 'run', 'download'])
        destination = Path(args[args.index('--dir') + 1])
        destination.mkdir(parents=True)
        if args[args.index('--name') + 1].startswith('xo-ci-reuse-receipt-'):
            (destination / 'receipt.json').write_text(json.dumps(self.receipt))
        return ''

    def restore(self):
        return reuse.restore(self.directory / 'candidate', self.controller,
                             self.directory / 'result.json', ['xo-latest'])

    def pinned_workflow(self):
        fixture = ROOT / 'tests/fixtures/reuse/ci-pr-export-disabled.yml'
        (self.controller / reuse.WORKFLOW).write_bytes(fixture.read_bytes())
        self.receipt['workflowSha256'] = reuse.digest(fixture)

    def queue_candidate(self):
        self.receipt.update(event='merge_group', ref='refs/heads/gh-readonly-queue/main/pr-97-' + CONTROLLER)
        self.run.update(event='merge_group', head_sha=SOURCE,
                        head_branch=self.receipt['ref'].removeprefix('refs/heads/'))

    def test_pinned_contract_cannot_export_or_attest_pr_receipts(self):
        path = ROOT / 'tests/fixtures/reuse/ci-pr-export-disabled.yml'
        self.assertIn(reuse.digest(path), reuse.NO_PR_RECEIPT_WORKFLOWS)
        workflow = yaml.safe_load(path.read_text())
        disabled = "${{ github.event_name != 'pull_request' && (github.event_name != 'workflow_dispatch' || inputs.export_reuse_payload) && 'true' || 'false' }}"
        for job in ('preflight', 'validate'):
            self.assertEqual(workflow['jobs'][job]['env']['XO_NIXPKG_EXPORT_REUSE_PAYLOAD'], disabled)
        self.assertEqual(workflow['jobs']['attest-builds']['if'],
                         "github.event_name != 'pull_request' && github.event_name != 'pull_request_review' && needs.validate.outputs.cache_eligible == 'true'")
        receipts = [s for s in workflow['jobs']['validate']['steps']
                    if s.get('with', {}).get('name', '').startswith('xo-ci-reuse-')]
        self.assertEqual(len(receipts), 2)
        self.assertTrue(all(s['if'] == "steps.trusted.outputs.cache_eligible == 'true'" for s in receipts))

    def test_thirty_impossible_pr_runs_use_one_listing_zero_artifact_calls(self):
        self.pinned_workflow()
        self.runs = [dict(self.run, id=200 + i) for i in range(30)]
        with patch.object(reuse, 'api', side_effect=self.api) as calls, \
             patch.object(reuse, 'digest', wraps=reuse.digest) as digests:
            self.assertEqual(self.restore()['status'], 'miss')
        self.assertEqual(len(calls.call_args_list), 1)
        self.assertIn('/actions/workflows/ci.yml/runs?', calls.call_args.args[0])
        self.assertEqual(digests.call_count, 1)
        self.download.assert_not_called()
        self.attestation.assert_not_called()
        self.transport.restore.assert_not_called()

    def test_mixed_pr_runs_still_reach_authenticated_queue_hit(self):
        self.pinned_workflow()
        skipped = [dict(self.run, id=200 + i) for i in range(12)]
        self.queue_candidate()
        self.runs = skipped + [self.run]
        with patch.object(reuse, 'api', side_effect=self.api) as calls:
            result = self.restore()
        self.assertEqual(result['status'], 'hit')
        listings = [c.args[0] for c in calls.call_args_list if c.args[0].endswith('/artifacts')]
        self.assertEqual(listings, ['repos/' + reuse.REPOSITORY + '/actions/runs/101/artifacts'])
        self.attestation.assert_called_once()
        self.transport.restore.assert_called_once()
        self.native.assert_called_once()

    def test_unknown_workflow_keeps_historical_pr_discovery_and_validation(self):
        self.assertNotIn(reuse.digest(self.controller / reuse.WORKFLOW), reuse.NO_PR_RECEIPT_WORKFLOWS)
        with patch.object(reuse, 'api', side_effect=self.api) as calls:
            self.assertEqual(self.restore()['status'], 'hit')
        self.assertTrue(any(c.args[0].endswith('/actions/runs/101/artifacts') for c in calls.call_args_list))
        self.attestation.assert_called_once()
        self.transport.restore.assert_called_once()

    def test_selected_queue_malformed_output_or_signature_still_fails(self):
        self.pinned_workflow()
        self.queue_candidate()
        self.attestation.side_effect = ValueError('signature invalid')
        with self.assertRaisesRegex(ValueError, 'signature invalid'):
            self.restore()
        self.attestation.side_effect = None
        self.receipt['outputs']['xo-latest']['storePath'] = '/tmp/forged'
        with self.assertRaisesRegex(ValueError, 'Invalid authenticated output'):
            self.restore()
        self.transport.restore.assert_not_called()
        self.native.assert_not_called()

    def test_explicitly_disabled_imports_do_not_discover_or_evaluate_artifacts(self):
        with patch.dict(os.environ, {'XO_NIXPKG_REUSE_BUILDS': 'false'}), \
             patch.object(reuse, 'api') as discovery, \
             patch.object(reuse, 'identity') as evaluate:
            result = self.restore()
        self.assertEqual(result['status'], 'miss')
        self.assertEqual(result['reason'], 'Actions artifact imports disabled')
        self.assertFalse(result['authorityClaim'])
        self.assertEqual(json.loads((self.directory / 'result.json').read_text()), result)
        discovery.assert_not_called()
        evaluate.assert_not_called()
        self.download.assert_not_called()
        self.attestation.assert_not_called()
        self.transport.restore.assert_not_called()
        self.native.assert_not_called()

    def test_import_option_rejects_invalid_values_before_discovery(self):
        for value in ('', 'False', '0', 'yes', 'true\n'):
            with self.subTest(value=value), \
                 patch.dict(os.environ, {'XO_NIXPKG_REUSE_BUILDS': value}), \
                 patch.object(reuse, 'api') as discovery:
                with self.assertRaisesRegex(ValueError, 'must be true or false'):
                    self.restore()
                discovery.assert_not_called()
        self.transport.restore.assert_not_called()

    def test_authenticated_hit_imports_expected_nar_and_physically_verifies_without_build(self):
        result = self.restore()
        self.assertEqual(result['status'], 'hit')
        self.assertEqual(result['matchedOutputs'], ['xo-latest'])
        self.assertFalse(result['authorityClaim'])
        self.attestation.assert_called_once()
        self.transport.restore.assert_called_once()
        self.assertEqual(self.transport.restore.call_args.args[1:],
                         (self.receipt['transport'], [{'storePath': OUTPUT, 'narHash': NAR_HASH}]))
        self.native.assert_called_once()
        self.assertEqual(self.native.call_args.args[1:],
                         ('store', 'verify', '--no-trust', '--recursive', OUTPUT))

    def test_no_credentials_no_runs_expired_and_different_tree_are_cache_misses(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.restore()['status'], 'miss')
        self.download.assert_not_called()
        self.runs = []
        self.assertEqual(self.restore()['status'], 'miss')
        self.runs = [self.run]
        self.artifacts[0]['expired'] = True
        self.assertEqual(self.restore()['status'], 'miss')
        self.download.assert_not_called()
        self.artifacts[0]['expired'] = False
        self.receipt['tree'] = 'e' * 40
        self.assertEqual(self.restore()['status'], 'miss')
        self.transport.restore.assert_not_called()

    def test_missing_historical_pr_association_is_cold_build_miss(self):
        # GitHub can drop a merged PR's association from historical run metadata.
        for association in ([], None):
            with self.subTest(association=association):
                if association is None:
                    self.run.pop('pull_requests', None)
                else:
                    self.run['pull_requests'] = association
                result = self.restore()
                self.assertEqual(result['status'], 'miss')
        self.assertFalse(result['authorityClaim'])
        self.attestation.assert_not_called()
        self.transport.restore.assert_not_called()
        self.native.assert_not_called()
        self.assertEqual(json.loads((self.directory / 'result.json').read_text()), result)

    def test_missing_pr_association_continues_to_an_authenticated_candidate(self):
        unavailable = dict(self.run, id=102, pull_requests=[])
        self.runs = [unavailable, self.run]
        original_api = self.api

        def api(path):
            if path.endswith('/actions/runs/102/attempts/2'):
                return copy.deepcopy(unavailable)
            if path.endswith('/actions/runs/102/artifacts'):
                return {'artifacts': [dict(self.artifacts[0], name='xo-ci-reuse-receipt-102-2')]}
            return original_api(path)

        def download(args, **kwargs):
            if args[3] == '102':
                destination = Path(args[args.index('--dir') + 1])
                destination.mkdir(parents=True)
                (destination / 'receipt.json').write_text(json.dumps(dict(self.receipt, runId=102)))
                return ''
            return self.command(args, **kwargs)

        with patch.object(reuse, 'api', side_effect=api), \
             patch.object(reuse, 'command', side_effect=download):
            result = self.restore()
        self.assertEqual(result['status'], 'hit')
        self.assertEqual(result['runId'], 101)
        self.attestation.assert_called_once()
        self.transport.restore.assert_called_once()

    def test_invalid_supplied_pr_provenance_remains_a_hard_failure(self):
        original = copy.deepcopy(self.run['pull_requests'])
        for association in (None, {}, 'untrusted', original * 2,
                            [dict(original[0], base=dict(original[0]['base'], sha='f' * 40))]):
            with self.subTest(association=association):
                self.run['pull_requests'] = association
                with self.assertRaises(ValueError):
                    self.restore()
                self.assertFalse((self.directory / 'result.json').exists())
        self.attestation.assert_not_called()
        self.transport.restore.assert_not_called()
        self.native.assert_not_called()

    def test_authenticated_previous_controller_bytes_are_cold_build_misses(self):
        for key in ('launcherSha256', 'workflowSha256'):
            with self.subTest(key=key):
                original = self.receipt[key]
                # Independently queried historical blobs agree with this receipt.
                self.receipt[key] = '0' * 64
                result = self.restore()
                self.assertEqual(result['status'], 'miss')
                self.assertFalse(result['authorityClaim'])
                self.receipt[key] = original
        self.assertEqual(self.attestation.call_count, 2)
        self.transport.restore.assert_not_called()
        self.native.assert_not_called()

    def test_previous_controller_still_requires_valid_attestation_and_receipt(self):
        self.receipt['launcherSha256'] = '0' * 64
        self.attestation.side_effect = ValueError('signature invalid')
        with self.assertRaisesRegex(ValueError, 'signature invalid'):
            self.restore()
        self.attestation.side_effect = None
        self.receipt['outputs']['xo-latest']['storePath'] = '/tmp/forged-output'
        with self.assertRaisesRegex(ValueError, 'Invalid authenticated output'):
            self.restore()
        self.transport.restore.assert_not_called()
        self.native.assert_not_called()
        self.assertFalse((self.directory / 'result.json').exists())

    def test_authenticated_old_policy_is_cache_miss_without_import(self):
        self.receipt['repositorySecretPolicy'] = {
            'policyId': 'github-native-secret-observation-v1', 'policySha256': '0' * 64}
        result = self.restore()
        self.assertEqual(result['status'], 'miss')
        self.assertFalse(result['authorityClaim'])
        self.attestation.assert_called_once()
        self.transport.restore.assert_not_called()
        self.native.assert_not_called()

    def test_old_policy_does_not_hide_bad_signature_or_output(self):
        self.receipt['repositorySecretPolicy'] = {
            'policyId': 'github-native-secret-observation-v1', 'policySha256': '0' * 64}
        self.attestation.side_effect = ValueError('signature invalid')
        with self.assertRaisesRegex(ValueError, 'signature invalid'): self.restore()
        self.attestation.side_effect = None
        self.receipt['outputs']['xo-latest']['storePath'] = '/tmp/forged'
        with self.assertRaisesRegex(ValueError, 'Invalid authenticated output'): self.restore()
        self.transport.restore.assert_not_called()
        self.native.assert_not_called()
        self.assertFalse((self.directory / 'result.json').exists())

    def test_changed_evaluated_derivation_cannot_reuse_same_named_output(self):
        self.evaluated['derivation'] = '/nix/store/' + '4' * 32 + '-changed.drv'
        self.assertEqual(self.restore()['status'], 'miss')
        self.transport.restore.assert_not_called()
        self.native.assert_not_called()

    def test_optional_timeout_before_import_is_a_miss(self):
        self.download.side_effect = subprocess.TimeoutExpired(['gh', 'run', 'download'], 180)
        result = self.restore()
        self.assertEqual(result['status'], 'miss')
        self.assertEqual(result['reason'], 'optional-transport-timeout')
        self.transport.restore.assert_not_called()

    def test_timeout_after_import_begins_blocks_without_build_fallback(self):
        self.transport.restore.side_effect = subprocess.TimeoutExpired(['nix', 'copy'], 600)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.restore()
        self.assertFalse((self.directory / 'result.json').exists())

    def test_same_store_path_and_derivation_with_forged_nar_is_hard_failure(self):
        # The authenticated transport must detect bytes that do not match its anchored NAR hash.
        self.transport.restore.side_effect = ValueError('Physical NAR does not match authenticated hash')
        with self.assertRaisesRegex(ValueError, 'NAR'): self.restore()
        self.native.assert_not_called()
        self.assertFalse((self.directory / 'result.json').exists())

    def test_database_metadata_alone_cannot_replace_physical_nar_verification(self):
        self.native.side_effect = subprocess.CalledProcessError(1, ['/nix/store/trusted-nix/bin/nix', 'store', 'verify'])
        with self.assertRaises(subprocess.CalledProcessError): self.restore()
        self.assertFalse((self.directory / 'result.json').exists())

    def test_corrupt_signature_or_producer_is_hard_failure(self):
        self.attestation.side_effect = ValueError('signature invalid')
        with self.assertRaisesRegex(ValueError, 'signature'): self.restore()
        self.transport.restore.assert_not_called()
        self.attestation.side_effect = None
        self.run['head_repository'] = {'full_name': 'attacker/repo'}
        with self.assertRaisesRegex(ValueError, 'producer'): self.restore()

    def test_artifact_run_attempt_and_output_payload_substitutions_rejected(self):
        self.receipt['runAttempt'] = 3
        # Even a separately valid attempt-3 receipt cannot be substituted into
        # the attempt-2 artifact selected from the completed-run API response.
        original_api = self.api
        def swapped_attempt(path):
            if path.endswith('/actions/runs/101/attempts/3'):
                return dict(self.run, run_attempt=3)
            return original_api(path)
        with patch.object(reuse, 'api', side_effect=swapped_attempt):
            with self.assertRaisesRegex(ValueError, 'Artifact/run substitution'): self.restore()
        self.receipt['runAttempt'] = 2
        self.receipt['outputs']['xo-latest']['storePath'] = '/tmp/not-a-store-output'
        with self.assertRaises(ValueError): self.restore()
        self.transport.restore.assert_not_called()

    def test_ambiguous_or_oversized_artifacts_are_hard_failure(self):
        self.artifacts *= 2
        with self.assertRaisesRegex(ValueError, 'Ambiguous'): self.restore()
        self.artifacts = self.artifacts[:1]
        self.artifacts[0]['size_in_bytes'] = 4 * 1024**2 + 1
        with self.assertRaisesRegex(ValueError, 'oversized'): self.restore()


if __name__ == '__main__':
    unittest.main()
