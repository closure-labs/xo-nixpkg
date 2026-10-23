"""Immutable Git bytes may be reused; main and human authority stay live."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / 'nix/automation/decisions'
if not CORE.is_dir():
    CORE = ROOT / 'ci/decisions'
sys.path.insert(0, str(CORE))
import common
import decision_authority as authority
from test_authority import GitHub, PROPOSAL, REPO, BOT, mod, verify


def encoded(value):
    raw = json.dumps(value, sort_keys=True).encode()
    sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return raw, {'sha': sha, 'size': len(raw), 'encoding': 'base64',
                 'content': base64.b64encode(raw).decode()}


class GitBlobReuse(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.environment = patch.dict(os.environ, {
            'RUNNER_TEMP': self.temporary.name, 'GITHUB_REPOSITORY': REPO,
            'GITHUB_SHA': 'c' * 40, 'GITHUB_RUN_ID': '123',
            'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'controller'})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.proposal = copy.deepcopy(PROPOSAL)
        self.raw, self.blob = encoded(self.proposal)
        self.calls = []
        self.main = 'a' * 40

    def api(self, endpoint):
        self.calls.append(endpoint)
        if endpoint.endswith('/git/ref/heads/main'):
            return {'object': {'sha': self.main}}
        if '/git/trees/' in endpoint:
            return {'truncated': False, 'tree': [{
                'path': authority.proposal_path(self.proposal), 'type': 'blob',
                'mode': '100644', 'sha': self.blob['sha'], 'size': self.blob['size']}]}
        if '/git/blobs/' in endpoint:
            return copy.deepcopy(self.blob)
        if '/contents/' in endpoint:
            return {'type': 'file', 'encoding': 'none', 'sha': self.blob['sha'], 'size': self.blob['size']}
        raise AssertionError(endpoint)

    def ledger(self):
        return common.ledger({'repository': REPO}, self.api)

    def test_repeated_ledger_reads_fresh_main_and_tree_but_one_blob(self):
        first = self.ledger()
        second = self.ledger()
        self.assertEqual(first, second)
        self.assertEqual(sum('/git/blobs/' in c for c in self.calls), 1)
        self.assertEqual(sum('/git/ref/heads/main' in c for c in self.calls), 2)
        self.assertEqual(sum('/git/trees/' in c for c in self.calls), 2)
        self.assertFalse(any('/contents/' in c for c in self.calls))

    def test_observations_distinguish_verified_bytes_without_authority_data(self):
        self.ledger()
        self.ledger()
        path = authority.blob_cache_path(REPO, self.blob['sha']).parent / 'observations.jsonl'
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual([row['reused'] for row in rows], [False, True])
        self.assertEqual(rows[0], dict(schema=1, repository=REPO, blob=self.blob['sha'],
                                      bytes=len(self.raw), reused=False, inline=False))

    def test_observation_symlink_cannot_overwrite_another_file(self):
        self.ledger()
        path = authority.blob_cache_path(REPO, self.blob['sha']).parent / 'observations.jsonl'
        path.unlink()
        target = Path(self.temporary.name) / 'target'
        target.write_text('unchanged')
        path.symlink_to(target)
        with self.assertRaises(OSError):
            self.ledger()
        self.assertEqual(target.read_text(), 'unchanged')

    def test_changed_main_and_blob_are_observed(self):
        self.ledger()
        self.main = 'b' * 40
        self.proposal['payload']['disposition'] = 'rejected'
        self.raw, self.blob = encoded(self.proposal)
        revision, records = self.ledger()
        self.assertEqual(revision, self.main)
        self.assertEqual(next(iter(records.values()))['payload']['disposition'], 'rejected')
        self.assertEqual(sum('/git/blobs/' in c for c in self.calls), 2)

    def test_decoded_results_do_not_share_mutable_objects(self):
        _, records = self.ledger()
        next(iter(records.values()))['payload']['disposition'] = 'forged'
        self.assertEqual(next(iter(self.ledger()[1].values()))['payload']['disposition'], 'accepted')

    def test_content_metadata_remains_fresh_on_raw_blob_hit(self):
        for _ in range(2):
            self.assertEqual(authority.document_at(self.api, REPO, 'policy.json', self.main), self.proposal)
        self.assertEqual(sum('/contents/' in c for c in self.calls), 2)
        self.assertEqual(sum('/git/blobs/' in c for c in self.calls), 1)

    def test_raw_cache_corruption_blocks_without_redownload(self):
        self.ledger()
        cache = authority.blob_cache_path(REPO, self.blob['sha'])
        cache.write_bytes(b'x' * len(self.raw))
        with self.assertRaisesRegex(authority.AuthorityError, 'blob'):
            self.ledger()
        self.assertEqual(sum('/git/blobs/' in c for c in self.calls), 1)

    def test_cache_symlink_is_rejected(self):
        self.ledger()
        cache = authority.blob_cache_path(REPO, self.blob['sha'])
        saved = cache.with_name('saved')
        cache.rename(saved)
        cache.symlink_to(saved)
        with self.assertRaises(authority.AuthorityError):
            self.ledger()

    def test_cache_fifo_is_rejected_without_waiting_for_a_writer(self):
        self.ledger()
        cache = authority.blob_cache_path(REPO, self.blob['sha'])
        cache.unlink()
        os.mkfifo(cache)
        with self.assertRaises(authority.AuthorityError):
            self.ledger()

    def test_cache_parent_symlink_is_rejected(self):
        self.ledger()
        cache = authority.blob_cache_path(REPO, self.blob['sha'])
        moved = cache.parent.with_name('moved')
        cache.parent.rename(moved)
        cache.parent.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(authority.AuthorityError):
            self.ledger()

    def test_parent_replaced_during_download_cannot_escape_runner_root(self):
        cache = authority.blob_cache_path(REPO, self.blob['sha'])
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary)
            def swapped(endpoint):
                cache.parent.parent.mkdir(parents=True, exist_ok=True)
                cache.parent.symlink_to(outside, target_is_directory=True)
                return self.api(endpoint)
            with self.assertRaises(authority.AuthorityError):
                authority.document_blob(swapped, REPO, self.blob['sha'], self.blob['size'])
            self.assertEqual(list(outside.iterdir()), [])

    def test_job_run_revision_repository_and_verifier_change_cache_scope(self):
        original = authority.blob_cache_path(REPO, self.blob['sha'])
        for field, value in [('GITHUB_JOB', 'another_job'), ('GITHUB_RUN_ID', '124'),
                             ('GITHUB_SHA', 'd' * 40), ('GITHUB_REPOSITORY', 'other/repo')]:
            with self.subTest(field=field), patch.dict(os.environ, {field: value}):
                self.assertNotEqual(authority.blob_cache_path(REPO, self.blob['sha']), original)
        self.assertNotEqual(authority.blob_cache_path('other/repo', self.blob['sha']), original)
        with patch.object(authority.Path, 'read_bytes', return_value=b'another verifier'):
            self.assertNotEqual(authority.blob_cache_path(REPO, self.blob['sha']), original)

    def test_invalid_job_scope_blocks(self):
        for field, value in [('GITHUB_RUN_ATTEMPT', '0'), ('GITHUB_JOB', '../other'),
                             ('RUNNER_TEMP', 'relative'), ('GITHUB_SHA', 'not-a-sha')]:
            with self.subTest(field=field), patch.dict(os.environ, {field: value}), \
                    self.assertRaises(authority.AuthorityError):
                self.ledger()

    def test_new_attempt_requires_new_materialization(self):
        self.ledger()
        with patch.dict(os.environ, {'GITHUB_RUN_ATTEMPT': '2'}):
            self.ledger()
        self.assertEqual(sum('/git/blobs/' in c for c in self.calls), 2)

    def test_no_hosted_job_preserves_uncached_calls(self):
        with patch.dict(os.environ, {'GITHUB_JOB': ''}):
            self.ledger()
            self.ledger()
        self.assertEqual(sum('/git/blobs/' in c for c in self.calls), 2)

    def test_bad_blob_identity_and_size_never_enter_cache(self):
        self.blob['sha'] = 'f' * 40
        with self.assertRaises(authority.AuthorityError):
            self.ledger()
        self.blob['size'] = True
        with self.assertRaises(authority.AuthorityError):
            self.ledger()

    def test_invalid_json_is_rejected_again_on_a_byte_cache_hit(self):
        raw = b'{"duplicate":1,"duplicate":2}'
        identity = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        blob = dict(sha=identity, size=len(raw), encoding='base64', content=base64.b64encode(raw).decode())
        for _ in range(2):
            with self.assertRaisesRegex(authority.AuthorityError, 'Invalid proposal blob'):
                authority.document_blob(lambda _: blob, REPO, identity, len(raw))

    def test_malformed_current_inline_bytes_block_even_with_a_cache_hit(self):
        self.ledger()
        inline = dict(self.blob, content=base64.b64encode(b'x' * len(self.raw)).decode())
        with self.assertRaises(authority.AuthorityError):
            authority.document_blob(self.api, REPO, self.blob['sha'], self.blob['size'], inline=inline)

    def test_failed_blob_download_does_not_seed_cache(self):
        with self.assertRaisesRegex(authority.AuthorityError, 'unavailable'):
            authority.document_blob(lambda _: (_ for _ in ()).throw(authority.AuthorityError('unavailable')),
                                    REPO, self.blob['sha'], self.blob['size'])
        self.assertFalse(authority.blob_cache_path(REPO, self.blob['sha']).exists())

    def test_metadata_failure_after_hit_is_not_an_empty_ledger(self):
        self.ledger()
        with self.assertRaisesRegex(authority.AuthorityError, 'unavailable'):
            common.ledger({'repository': REPO}, lambda _: (_ for _ in ()).throw(authority.AuthorityError('unavailable')))

    def test_cache_hit_does_not_reuse_human_authority(self):
        api = GitHub()
        self.assertEqual(verify(api)['status'], 'authorized')
        api.reviews[0]['state'] = 'CHANGES_REQUESTED'
        with self.assertRaises(mod.HumanDecisionRequired):
            verify(api)
        self.assertGreaterEqual(sum('/reviews?' in c for c in api.calls), 2)

    def test_cache_hit_does_not_reuse_team_membership(self):
        api = GitHub()
        self.assertEqual(verify(api)['status'], 'authorized')
        api.memberships['maintainer'] = {'state': 'pending', 'role': 'member'}
        with self.assertRaises(mod.HumanDecisionRequired):
            verify(api)
        self.assertGreaterEqual(sum('/memberships/maintainer' in c for c in api.calls), 2)


if __name__ == '__main__':
    unittest.main()
