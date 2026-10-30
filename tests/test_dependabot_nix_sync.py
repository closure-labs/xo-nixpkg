# SPDX-License-Identifier: Apache-2.0
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sync_lock', ROOT / 'ci/sync-dependabot-lock.py')
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


def raw(value):
    return json.dumps(value, indent=2).encode() + b'\n'


def blob(value):
    return hashlib.sha1(b'blob ' + str(len(value)).encode() + b'\0' + value).hexdigest()


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.base, self.head = 'a' * 40, 'b' * 40
        self.flake = json.loads((ROOT / 'flake.lock').read_bytes())
        self.native = json.loads((ROOT / 'devenv.lock').read_bytes())
        self.new = copy.deepcopy(self.flake)
        self.new['nodes']['nixpkgs']['locked'].update(rev='c' * 40, narHash='sha256-' + 'A' * 43 + '=', lastModified=1800000000)
        self.candidate_native = copy.deepcopy(self.native)
        self.pr = {'number': 9, 'state': 'open', 'merged': False, 'changed_files': 1,
                   'user': {'id': 49699333, 'login': 'dependabot[bot]', 'type': 'Bot'},
                   'base': {'ref': 'main', 'sha': self.base, 'repo': {'full_name': sync.REPO}},
                   'head': {'ref': 'dependabot/nix/nixpkgs-ccccccc', 'sha': self.head, 'repo': {'full_name': sync.REPO}}}
        self.files = [{'filename': 'flake.lock', 'status': 'modified'}]
        self.writes = []
        self.mode = '100644'
        self.truncated = False
        self.head_reads = 0
        self.race = False
        self.discovery = [self.pr]

    def synchronize(self):
        return sync.synchronize(*map(raw, (self.flake, self.new, self.native, self.candidate_native)))

    def api(self, endpoint, body=None, method=None):
        if body is not None:
            self.writes.append((endpoint, body))
            self.assertEqual(endpoint, 'graphql')
            return {'data': {'createCommitOnBranch': {'commit': {'oid': 'd' * 40}}}}
        if endpoint == 'pulls?state=open&base=main&per_page=100':
            return self.discovery
        if endpoint == 'git/ref/heads/main':
            return {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': self.base}}
        if endpoint == 'pulls/9':
            self.head_reads += 1
            result = copy.deepcopy(self.pr)
            if self.race and self.head_reads >= 2:
                result['head']['sha'] = 'e' * 40
            return result
        if endpoint == 'pulls/9/files?per_page=100':
            return self.files
        if endpoint == 'commits/' + 'd' * 40:
            return {'sha': 'd' * 40, 'parents': [{'sha': self.head}],
                    'author': {'login': 'cl-decider[bot]', 'type': 'Bot'},
                    'commit': {'verification': {'verified': True, 'reason': 'valid'}}}
        if endpoint.startswith('git/commits/'):
            sha = endpoint.rsplit('/', 1)[1]
            return {'sha': sha, 'tree': {'sha': sha}}
        if endpoint.startswith('git/trees/'):
            sha = endpoint.rsplit('/', 1)[1]
            values = (self.flake, self.native) if sha == self.base else (self.new, self.candidate_native)
            if sha == 'd' * 40:
                values = (self.new, json.loads(self.synchronize()))
            return {'sha': sha, 'truncated': self.truncated, 'tree': [
                {'path': path, 'mode': self.mode, 'type': 'blob', 'sha': blob(raw(value))}
                for path, value in zip(('flake.lock', 'devenv.lock'), values)]}
        if endpoint.startswith('contents/'):
            path, sha = endpoint[len('contents/'):].split('?ref=')
            values = (self.flake, self.native) if sha == self.base else (self.new, self.candidate_native)
            content = raw(values[0 if path == 'flake.lock' else 1])
            return {'type': 'file', 'path': path, 'encoding': 'base64', 'size': len(content),
                    'sha': blob(content), 'content': base64.b64encode(content).decode()}
        self.fail(endpoint)

    def test_exact_node_only_and_idempotent(self):
        output = json.loads(self.synchronize())
        expected = copy.deepcopy(self.native)
        expected['nodes']['nixpkgs']['locked'] = self.new['nodes']['nixpkgs']['locked']
        self.assertEqual(output, expected)
        self.candidate_native = output
        self.assertIsNone(self.synchronize())

    def test_other_flake_input_refused(self):
        self.new['nodes']['xo-latest']['locked']['rev'] = 'f' * 40
        with self.assertRaises(ValueError): self.synchronize()

    def test_other_native_module_refused(self):
        self.candidate_native['nodes']['devenv']['locked']['rev'] = 'f' * 40
        with self.assertRaises(ValueError): self.synchronize()

    def test_invalid_source_hash_ref_revision(self):
        for key, value in [('owner', 'attacker'), ('rev', 'bad'), ('narHash', 'sha256-bad'), ('lastModified', True)]:
            with self.subTest(key=key):
                old = self.new['nodes']['nixpkgs']['locked'][key]
                self.new['nodes']['nixpkgs']['locked'][key] = value
                with self.assertRaises(ValueError): self.synchronize()
                self.new['nodes']['nixpkgs']['locked'][key] = old
        self.new['nodes']['nixpkgs']['original']['ref'] = 'master'
        with self.assertRaises(ValueError): self.synchronize()

    def test_duplicate_json_and_size(self):
        with self.assertRaises(ValueError): sync.parse(b'{"x":1,"x":2}')
        with self.assertRaises(ValueError): sync.parse(b' ' * (sync.LIMIT + 1))

    def test_base_pair_inconsistency_refused(self):
        self.native['nodes']['nixpkgs']['locked']['rev'] = 'f' * 40
        with self.assertRaises(ValueError): self.synchronize()

    def test_unchanged_revision_refused(self):
        self.new['nodes']['nixpkgs']['locked']['rev'] = self.flake['nodes']['nixpkgs']['locked']['rev']
        with self.assertRaises(ValueError): self.synchronize()

    def test_readonly_plan_makes_no_writes(self):
        branch, output = sync.plan(9, self.base, self.head, self.api)
        self.assertIsNotNone(output)
        self.assertEqual(branch, self.pr['head']['ref'])
        self.assertEqual(self.writes, [])

    def test_atomic_writer_only_native_lock(self):
        self.assertTrue(sync.execute(9, self.base, self.head, self.api)['changed'])
        self.assertEqual(len(self.writes), 1)
        args = self.writes[0][1]['variables']['input']
        self.assertEqual(args['expectedHeadOid'], self.head)
        self.assertIn('[dependabot skip]', args['message']['headline'])
        self.assertEqual(args['branch'], {'repositoryNameWithOwner': sync.REPO, 'branchName': self.pr['head']['ref']})
        self.assertEqual(set(args['fileChanges']), {'additions'})
        self.assertEqual([x['path'] for x in args['fileChanges']['additions']], ['devenv.lock'])
        self.assertEqual(base64.b64decode(args['fileChanges']['additions'][0]['contents']), self.synchronize())

    def test_idempotent_writer_no_write(self):
        self.candidate_native = json.loads(self.synchronize())
        self.pr['changed_files'] = 2
        self.files.append({'filename': 'devenv.lock', 'status': 'modified'})
        self.assertFalse(sync.execute(9, self.base, self.head, self.api)['changed'])
        self.assertEqual(self.writes, [])

    def test_actor_and_branch_base_head_guards(self):
        for part, field, value in [('user','id', 1), ('user','type','User'), ('head','ref','manual/nix'),
                                   ('head','sha','e'*40), ('base','ref','develop'), ('base','sha','e'*40)]:
            with self.subTest(part=part, field=field):
                pr = copy.deepcopy(self.pr); pr[part][field] = value
                with self.assertRaises(ValueError): sync.pr_identity(pr, 9, self.base, self.head)

    def test_unexpected_path_rename_or_count(self):
        for files in ([{'filename':'flake.nix','status':'modified'}],
                      [{'filename':'flake.lock','status':'renamed'}],
                      [{'filename':'flake.lock','status':'modified','previous_filename':'x'}], []):
            self.files = files
            with self.assertRaises(ValueError): sync.plan(9, self.base, self.head, self.api)

    def test_nonordinary_lock_file(self):
        for mode in ('120000','100755','160000'):
            self.mode = mode
            with self.assertRaises(ValueError): sync.plan(9, self.base, self.head, self.api)

    def test_truncated_tree(self):
        self.truncated = True
        with self.assertRaises(ValueError): sync.plan(9, self.base, self.head, self.api)

    def test_head_race_refuses_before_any_write(self):
        self.race = True
        with self.assertRaises(ValueError): sync.execute(9, self.base, self.head, self.api)
        self.assertEqual(self.writes, [])

    def test_uncertain_write_is_not_retried(self):
        def uncertain(endpoint, body=None, method=None):
            if body is not None:
                self.writes.append(endpoint)
                return {'errors': [{'message': 'unknown'}]}
            return self.api(endpoint)
        with self.assertRaises(ValueError): sync.execute(9, self.base, self.head, uncertain)
        self.assertEqual(self.writes, ['graphql'])

    def test_closed_and_fork_refused(self):
        for change in ('closed', 'fork'):
            pr = copy.deepcopy(self.pr)
            if change == 'closed': pr['state'] = 'closed'
            else: pr['head']['repo']['full_name'] = 'attacker/fork'
            with self.assertRaises(ValueError): sync.pr_identity(pr, 9, self.base, self.head)

    def test_main_movement_and_digest_mismatch(self):
        for target in ('main', 'digest'):
            def changed(endpoint, body=None, method=None):
                result = self.api(endpoint, body, method)
                if target == 'main' and endpoint == 'git/ref/heads/main':
                    result['object']['sha'] = 'e' * 40
                if target == 'digest' and endpoint.startswith('contents/'):
                    result['sha'] = 'e' * 40
                return result
            with self.assertRaises(ValueError): sync.execute(9, self.base, self.head, changed)
            self.assertEqual(self.writes, [])

    def test_malformed_root_and_unrelated_added_node(self):
        self.new['nodes']['unrelated'] = {'locked': {}}
        with self.assertRaises(ValueError): self.synchronize()
        del self.new['nodes']['unrelated']
        self.flake['nodes']['root']['inputs'] = []
        with self.assertRaises(ValueError): self.synchronize()

    def test_atomic_conflict_does_not_retry(self):
        def conflict(endpoint, body=None, method=None):
            if body is not None:
                self.writes.append(endpoint)
                return {'errors': [{'type': 'STALE_DATA', 'message': 'expectedHeadOid mismatch'}]}
            return self.api(endpoint)
        with self.assertRaises(ValueError): sync.execute(9, self.base, self.head, conflict)
        self.assertEqual(self.writes, ['graphql'])

    def test_bad_publication_receipt_never_retries(self):
        for field in ('parent', 'author', 'signature', 'tree'):
            self.writes = []
            def bad(endpoint, body=None, method=None):
                result = self.api(endpoint, body, method)
                if endpoint == 'commits/' + 'd' * 40:
                    if field == 'parent': result['parents'] = []
                    if field == 'author': result['author']['login'] = 'other[bot]'
                    if field == 'signature': result['commit']['verification']['verified'] = False
                if endpoint == 'git/trees/' + 'd' * 40 and field == 'tree':
                    result['tree'][0]['sha'] = 'e' * 40
                return result
            with self.assertRaises(ValueError): sync.execute(9, self.base, self.head, bad)
            self.assertEqual(len(self.writes), 1)

    def test_discovery_zero_and_one(self):
        self.assertEqual(sync.discover(self.base, self.api),
                         {'changed': True, 'number': 9, 'head': self.head})
        self.discovery = []
        self.assertEqual(sync.discover(self.base, self.api), {'changed': False})
        self.assertEqual(self.writes, [])

    def test_discovery_multiple_incomplete_malformed(self):
        other = copy.deepcopy(self.pr); other['number'] = 10
        for response in ([self.pr, other], [self.pr] * 100, {}, [None], [{}], [self.pr, self.pr]):
            with self.subTest(response=str(response)[:50]):
                self.discovery = response
                with self.assertRaises(ValueError): sync.discover(self.base, self.api)
        self.assertEqual(self.writes, [])

    def test_discovery_candidate_race(self):
        self.race = True
        with self.assertRaises(ValueError): sync.discover(self.base, self.api)
        self.assertEqual(self.writes, [])

    def test_discovery_main_race_even_when_idle(self):
        self.discovery = []
        reads = 0
        def advancing(endpoint, body=None, method=None):
            nonlocal reads
            value = self.api(endpoint, body, method)
            if endpoint == 'git/ref/heads/main':
                reads += 1
                if reads > 1: value['object']['sha'] = 'f' * 40
            return value
        with self.assertRaises(ValueError): sync.discover(self.base, advancing)
        self.assertEqual(self.writes, [])

    def test_discovery_rejects_wrong_candidate_identity(self):
        for part, key, value in [('base', 'sha', 'f' * 40), ('user', 'login', 'wrong[bot]'),
                                 ('user', 'type', 'User'), ('head', 'repo', {'full_name': 'other/repo'})]:
            candidate = copy.deepcopy(self.pr); candidate[part][key] = value
            self.discovery = [candidate]
            with self.assertRaises(ValueError): sync.discover(self.base, self.api)
        self.assertEqual(self.writes, [])

    def test_workflow_never_executes_or_checks_out_candidate(self):
        text = (ROOT / '.github/workflows/dependabot-nix-lock.yml').read_text()
        self.assertNotIn('pull_request_target', text)
        self.assertIn('workflow_dispatch:', text)
        self.assertIn('cron: "17 * * * *"', text)
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn('run: python3 ci/sync-dependabot-lock.py --discover', text)
        self.assertIn("if: steps.plan.outputs.changed == 'true'", text)
        self.assertIn('ref: ${{ github.sha }}', text)
        self.assertNotIn('ref: ${{ github.event.pull_request.head.sha }}', text)
        self.assertNotIn('nix run', text)
        self.assertNotIn('setup-nix', text)
        self.assertIn('permission-contents: write', text)
        self.assertNotIn('permission-pull-requests: write', text)
        self.assertLess(text.index('id: plan'), text.index('id: writer'))


if __name__ == '__main__': unittest.main()
