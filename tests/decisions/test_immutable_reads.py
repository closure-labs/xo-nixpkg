"""Immutable read counts and unchanged live authority/race boundaries."""
from collections import Counter
from copy import deepcopy
import datetime as dt
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from test_authority import GitHub, REPO, BOT, MAIN
from test_product_authority import PublicationAPI
import common
import decision_authority as authority
import immutable_reads

PATH = 'automation/decisions/security/' + 'a' * 64 + '.json'
CONTENTS = f'repos/{REPO}/contents/{PATH}?ref=' + 'b' * 40
COMPARE = f'repos/{REPO}/compare/' + 'b' * 40 + '...' + 'c' * 40


class Reads(unittest.TestCase):
    def test_full_sha_facts_reuse_only_within_this_instance(self):
        calls = []
        value = PublicationAPI.blob({'public': 'fixture'})
        api = lambda e: calls.append(e) or deepcopy(value if '/contents/' in e else {'status': 'ahead'})
        reads = immutable_reads.GateReads(REPO, api)
        for endpoint in [CONTENTS, COMPARE]:
            self.assertEqual(reads(endpoint), reads(endpoint))
        self.assertEqual(calls, [CONTENTS, COMPARE])
        self.assertEqual(reads.hits, 2)
        immutable_reads.GateReads(REPO, api)(CONTENTS)
        self.assertEqual(calls, [CONTENTS, COMPARE, CONTENTS])

    def test_policy_and_all_mutable_surfaces_stay_live(self):
        calls = []
        reads = immutable_reads.GateReads(REPO, lambda e: calls.append(e) or {'status': 'ahead'})
        endpoints = [f'repos/{REPO}/git/ref/heads/main',
                     f'repos/{REPO}/contents/ci/decision-policy.json?ref=' + 'b' * 40,
                     f'repos/{REPO}/pulls/7', f'repos/{REPO}/pulls/7/files?per_page=100',
                     f'repos/{REPO}/pulls/7/reviews?per_page=100',
                     f'repos/{REPO}/issues/7/timeline?per_page=100',
                     f'repos/{REPO}/commits/' + 'b' * 40 + '/pulls?per_page=100',
                     f'repos/{REPO}/commits?path={PATH}&sha=main&per_page=1',
                     'orgs/closure-labs/teams/super-admins/members?per_page=100',
                     'orgs/closure-labs/teams/super-admins/memberships/maintainer',
                     f'repos/{REPO}/collaborators/maintainer/permission',
                     CONTENTS.replace('ref=' + 'b' * 40, 'ref=main'),
                     CONTENTS + '&ref=main', COMPARE.replace('b' * 40, 'main'),
                     COMPARE + '?page=1', CONTENTS.replace(REPO, 'other/repo')]
        for endpoint in endpoints:
            reads(endpoint); reads(endpoint)
        self.assertEqual(len(calls), 2 * len(endpoints))
        self.assertEqual(reads.hits, 0)

    def test_changed_revision_or_compare_pair_is_a_new_read(self):
        calls = []
        reads = immutable_reads.GateReads(REPO, lambda e: calls.append(e) or (
            PublicationAPI.blob({'fixture': True}) if '/contents/' in e else {'status': 'ahead'}))
        for endpoint in [CONTENTS, CONTENTS.replace('ref=' + 'b' * 40, 'ref=' + 'c' * 40),
                         COMPARE, COMPARE.replace('c' * 40, 'd' * 40)]:
            reads(endpoint)
        self.assertEqual(len(calls), 4)

    def test_errors_and_bad_metadata_are_never_cached(self):
        valid = PublicationAPI.blob({'fixture': True})
        invalid = [dict(valid, type='symlink'), dict(valid, size=True), dict(valid, sha='0' * 40),
                   dict(valid, content='corrupted'), dict(valid, target='other'),
                   dict(valid, submodule_git_url='public-but-wrong'), {'status': 'diverged'}]
        for bad in invalid:
            with self.subTest(bad=bad):
                endpoint = COMPARE if 'status' in bad else CONTENTS
                good = {'status': 'ahead'} if endpoint == COMPARE else valid
                calls = []
                def api(e):
                    calls.append(e)
                    return deepcopy(bad if len(calls) == 1 else good)
                reads = immutable_reads.GateReads(REPO, api)
                reads(endpoint); reads(endpoint); reads(endpoint)
                self.assertEqual(len(calls), 2)
        for status in [403, 404, 429, 500]:
            calls = []
            def api(e):
                calls.append(e)
                raise authority.AuthorityError('fixed HTTP ' + str(status))
            reads = immutable_reads.GateReads(REPO, api)
            for _ in range(2):
                with self.assertRaises(authority.AuthorityError):
                    reads(CONTENTS)
            self.assertEqual(len(calls), 2)
            self.assertEqual(reads.entries, {})

    def test_response_mutation_does_not_poison_retained_fact(self):
        value = PublicationAPI.blob({'fixture': True})
        reads = immutable_reads.GateReads(REPO, lambda _: value)
        first = reads(CONTENTS); first['type'] = 'symlink'
        second = reads(CONTENTS); self.assertEqual(second['type'], 'file')
        second['sha'] = '0' * 40
        self.assertNotEqual(reads(CONTENTS)['sha'], '0' * 40)

    def test_large_blob_metadata_reuse_does_not_skip_byte_validation(self):
        blob = PublicationAPI.blob({'fixture': True})
        metadata = dict(blob, encoding='none', content='')
        calls = []
        def api(endpoint):
            calls.append(endpoint)
            if '/contents/' in endpoint:
                return metadata
            return blob if sum('/git/blobs/' in p for p in calls) == 1 else dict(blob, content='corrupted')
        reads = immutable_reads.GateReads(REPO, api)
        with patch.dict(os.environ, {'RUNNER_TEMP': ''}):
            self.assertEqual(authority.document_at(reads, REPO, PATH, 'b' * 40), {'fixture': True})
            with self.assertRaises(ValueError):
                authority.document_at(reads, REPO, PATH, 'b' * 40)
        self.assertEqual(sum('/contents/' in p for p in calls), 1)
        self.assertEqual(sum('/git/blobs/' in p for p in calls), 2)

    def test_capacity_exhaustion_falls_back_to_live_reads(self):
        calls = []
        reads = immutable_reads.GateReads(REPO, lambda e: calls.append(e) or PublicationAPI.blob({'x': 1}))
        reads.MAX_ENTRIES = 1
        other = CONTENTS.replace('a' * 64, 'd' * 64)
        reads(CONTENTS); reads(CONTENTS); reads(other); reads(other)
        self.assertEqual(calls, [CONTENTS, other, other])
        reads.MAX_BYTES = 0
        reads(CONTENTS.replace('a' * 64, 'e' * 64))


class ChainAPI(PublicationAPI):
    """Eight historical security ancestors, one live leaf, one live product."""
    def __init__(self, rescan=False):
        super().__init__()
        if rescan:
            self.scan['producer']['revision'] = 'f' * 40
        template = deepcopy(self.risk)
        self.records = {}; self.origins = {}; self.by_number = {}
        prior = None
        for i in range(9):
            proposal = deepcopy(template)
            proposal['payload'].update(rationale='Reviewed fixture ' + str(i), supersedes=[prior] if prior else [])
            path = common.authority.proposal_path(proposal)
            number = 100 + i
            head, merge = f'{1000+i:040x}', f'{2000+i:040x}'
            github = GitHub(); github.proposal = proposal
            github.pr.update(number=number, merge_commit_sha=merge)
            github.pr['head']['sha'] = head
            github.reviews[0]['commit_id'] = head
            github.timeline[0]['commit_id'] = merge
            github.files = [{'filename': path, 'status': 'added'}]
            self.records[path] = proposal; self.origins[path] = (number, merge)
            self.by_number[number] = github
            prior = common.canonical_hash(proposal)
            self.risk, self.github = proposal, github
        self.approve_product()
        self.by_number[8] = self.product_github

    def __call__(self, endpoint):
        if endpoint == f'repos/{REPO}/actions/runs/5/attempts/2':
            value = super().__call__(endpoint)
            value['head_sha'] = self.scan['producer'].get('revision', self.scan['revision'])
            return value
        for path, (number, merge) in self.origins.items():
            if '/commits/' + merge + '/pulls?' in endpoint:
                return [deepcopy(self.by_number[number].pr)]
        match = re.search(r'/(pulls|issues)/([0-9]+)(?:/|$)', endpoint)
        if match and int(match[2]) in self.by_number:
            number = int(match[2])
            return self.by_number[number](endpoint.replace('/' + match[1] + '/' + str(number),
                                                          '/' + match[1] + '/7'))
        return super().__call__(endpoint)


class FullGate(unittest.TestCase):
    def invoke(self, optimized, mutate=None, rescan=False):
        service = ChainAPI(rescan=rescan); calls = []; seen = Counter()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scope = {'RUNNER_TEMP': temporary, 'GITHUB_REPOSITORY': REPO, 'GITHUB_SHA': MAIN,
                     'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'fixture'}
            registry = 'ghcr.io/' + REPO + '-decisions'
            with patch.dict(os.environ, scope), patch.object(common, 'attest', return_value=[]), \
                    patch.object(common.packets, 'REGISTRY', registry), \
                    patch.object(common.packets, 'REFERENCE', re.compile(re.escape(registry) + r'@sha256:[a-f0-9]{64}')):
                # Match the publisher's preexisting verified raw-Git-byte cache;
                # this warms no PR, review, membership or authorization result.
                common.ledger(service.policy, service)
                for name, value in [('scans', service.scan), ('product', service.product)]:
                    (root / (name + '.json')).write_text(json.dumps(value))
                def api(endpoint):
                    calls.append(endpoint); seen[endpoint] += 1
                    if mutate:
                        replacement = mutate(endpoint, seen, service)
                        if replacement is not None:
                            return replacement
                    return service(endpoint)
                invoke = common.gate if optimized else common._gate
                result = invoke(service.policy, root / 'scans.json', root / 'product.json', 'release', api)
                return result, calls

    def test_full_gate_counts_and_live_endpoint_sequence(self):
        before, old = self.invoke(False)
        after, new = self.invoke(True)
        self.assertEqual(before, after)
        self.assertEqual((len(old), len(new)), (302, 262))
        pattern = immutable_reads.GateReads(REPO, None).pattern
        mutable = lambda rows: [e for e in rows if not pattern.fullmatch(e)]
        self.assertEqual(mutable(old), mutable(new))
        self.assertEqual(sum('/contents/' in e for e in old) - sum('/contents/' in e for e in new), 30)
        self.assertEqual(sum('/compare/' in e for e in old) - sum('/compare/' in e for e in new), 10)
        # A distinct current rescan producer adds the two live ancestry reads.
        before, old = self.invoke(False, rescan=True)
        after, new = self.invoke(True, rescan=True)
        self.assertEqual(before, after)
        self.assertEqual((len(old), len(new)), (304, 264))
        self.assertEqual(mutable(old), mutable(new))

    def test_a_new_gate_does_not_inherit_structural_reads(self):
        self.assertEqual(len(self.invoke(True)[1]), 262)
        self.assertEqual(len(self.invoke(True)[1]), 262)

    def test_review_and_membership_withdrawal_still_block(self):
        def review(endpoint, seen, service):
            if '/pulls/8/reviews?' in endpoint and seen[endpoint] >= 2:
                service.product_github.reviews[0]['state'] = 'DISMISSED'
        def member(endpoint, seen, service):
            if '/memberships/maintainer' in endpoint and seen[endpoint] >= 2:
                return {'state': 'pending', 'role': 'member'}
        for mutation in (review, member):
            with self.subTest(mutation=mutation), self.assertRaises(authority.HumanDecisionRequired):
                self.invoke(True, mutation)

    def test_historical_pr_head_files_and_timeline_races_still_block(self):
        def head(endpoint, seen, service):
            if endpoint.endswith('/pulls/100') and seen[endpoint] >= 2:
                service.by_number[100].pr['head']['sha'] = 'f' * 40
        def files(endpoint, seen, service):
            if '/pulls/100/files?' in endpoint and seen[endpoint] >= 2:
                service.by_number[100].files.append({'filename': 'undeclared', 'status': 'added'})
        def timeline(endpoint, seen, service):
            if '/issues/100/timeline?' in endpoint and seen[endpoint] >= 2:
                service.by_number[100].timeline[0]['id'] += 1
        for mutation in (head, files, timeline):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.invoke(True, mutation)

    def test_final_live_main_read_still_blocks_concurrent_change(self):
        _, baseline = self.invoke(False)
        endpoint = f'repos/{REPO}/git/ref/heads/main'
        final = baseline.count(endpoint)
        def change(e, seen, service):
            if e == endpoint and seen[e] == final:
                return {'object': {'sha': 'f' * 40}}
        with self.assertRaisesRegex(ValueError, 'Protected main moved'):
            self.invoke(True, change)

    def test_policy_change_on_final_complete_tree_still_blocks(self):
        changed = None
        def change(endpoint, seen, service):
            nonlocal changed
            if '/git/trees/' in endpoint and seen[endpoint] >= 2:
                changed = service.blob(dict(service.policy, enabled=False))
                value = service(endpoint)
                for row in value['tree']:
                    if row['path'] == service.policy['policyPath']:
                        row.update(sha=changed['sha'], size=changed['size'])
                return value
            if changed and endpoint.endswith('/git/blobs/' + changed['sha']):
                return changed
        with self.assertRaisesRegex(ValueError, 'policy changed'):
            self.invoke(True, change)


if __name__ == '__main__':
    unittest.main()
