"""Publish through the native CLI against external API/signature fixtures."""
import base64
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from test_core import CFG, ROOT, NAR, SHA, scan
from test_authority import GitHub, REPO, BOT, MERGE
import common
import publication
import reconciliation


class PublicationAPI:
    def __init__(self):
        self.policy = dict(CFG, repository=REPO, botLogin=BOT, enabled=True)
        self.scan = dict(scan(), repository=REPO)
        self.product = {'schema': 1, 'repository': REPO, 'revision': SHA,
                        'products': {'maestro': {'storePath': ROOT, 'narHash': NAR}}, 'assets': {}}
        packet = {'reference': 'ghcr.io/' + REPO + '-decisions@sha256:' + 'a' * 64,
                  'sha256': 'b' * 64}
        self.risk = {'schema': 1, 'kind': 'security-findings', 'payload': {
            'disposition': 'accepted', 'rationale': 'Human reviewed complete risk scope.',
            'profiles': {p: common.evaluate(value, p)['findings'] for p, value in self.scan['profiles'].items()},
            'packet': packet, 'supersedes': []}}
        self.github = GitHub()
        self.github.proposal = self.risk
        self.path = common.authority.proposal_path(self.risk)
        self.github.files = [{'filename': self.path, 'status': 'added'}]
        self.records = {self.path: self.risk}
        self.origins = {self.path: (7, MERGE)}
        self.product_github = None
        self.revoke_product_on_final_check = False
        self.product_review_reads = 0

    def approve_product(self, identity=None):
        proposal = {'schema': 1, 'kind': 'release-product', 'payload': {
            'disposition': 'accepted', 'rationale': 'Human reviewed these exact immutable product bytes.',
            'product': deepcopy(identity if identity is not None else self.product),
            'packet': deepcopy(self.risk['payload']['packet']), 'supersedes': []}}
        path = common.authority.proposal_path(proposal)
        self.records[path] = proposal
        self.origins[path] = (8, 'd' * 40)
        self.product_github = GitHub()
        self.product_github.proposal = proposal
        self.product_github.pr.update(number=8, merge_commit_sha='d' * 40)
        self.product_github.pr['head']['sha'] = 'e' * 40
        self.product_github.reviews[0]['commit_id'] = 'e' * 40
        self.product_github.timeline[0]['commit_id'] = 'd' * 40
        self.product_github.files = [{'filename': path, 'status': 'added'}]

    @staticmethod
    def blob(document):
        data = json.dumps(document).encode()
        return {'type': 'file', 'sha': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(),
                'encoding': 'base64', 'size': len(data), 'content': base64.b64encode(data).decode()}

    def __call__(self, endpoint):
        if '/rules/branches/main' in endpoint:
            return [{'type': 'required_status_checks', 'parameters': {'required_status_checks': [
                {'context': 'Maintainer decision authority', 'integration_id': self.policy['appId']}]}}]
        if '/git/trees/' in endpoint:
            return {'truncated': False, 'tree': [
                dict(type='blob', mode='100644', path=path,
                     **{key: self.blob(value)[key] for key in ('sha', 'size')})
                for path, value in self.records.items()]}
        if '/git/blobs/' in endpoint:
            return next(self.blob(value) for value in self.records.values()
                        if endpoint.endswith('/' + self.blob(value)['sha']))
        if '/contents/' + self.policy['policyPath'] + '?' in endpoint:
            return self.blob(self.policy)
        if '/contents/' in endpoint:
            path = endpoint.split('/contents/', 1)[1].split('?', 1)[0]
            return self.blob(self.records[path])
        if '/commits?path=' in endpoint:
            path = parse_qs(urlsplit(endpoint).query)['path'][0]
            return [{'sha': self.origins[path][1]}]
        for number, merge in self.origins.values():
            if '/commits/' + merge + '/pulls?' in endpoint:
                return [deepcopy((self.github if number == 7 else self.product_github).pr)]
        if '/pulls/8' in endpoint or '/issues/8' in endpoint:
            if '/pulls/8/reviews?' in endpoint:
                self.product_review_reads += 1
                if self.revoke_product_on_final_check and self.product_review_reads >= 2:
                    self.product_github.reviews[0]['state'] = 'DISMISSED'
            return self.product_github(endpoint.replace('/pulls/8', '/pulls/7').replace('/issues/8', '/issues/7'))
        if endpoint == f'repos/{REPO}/actions/runs/5/attempts/2':
            return {'id': 5, 'run_attempt': 2, 'head_sha': SHA, 'head_branch': 'main', 'event': 'push',
                    'path': '.github/workflows/ci.yml', 'status': 'completed', 'conclusion': 'success',
                    'repository': {'full_name': REPO}}
        return self.github(endpoint)


class ProductAuthority(unittest.TestCase):
    def invoke(self, api, purpose):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, value in [('policy', api.policy), ('scans', api.scan), ('product', api.product)]:
                (root / (name + '.json')).write_text(json.dumps(value))
            args = ['publication', '--config', str(root / 'policy.json'), '--scans', str(root / 'scans.json'),
                    '--product', str(root / 'product.json'), '--purpose', purpose, '--output', str(root / 'result.json')]
            # Only external GitHub and signature-verification boundaries are fixtures.
            # Native policy, ledger, producer, risk, product, and human checks run.
            with patch.object(sys, 'argv', args), patch.object(common.authority, 'github_api', api), \
                    patch.object(common, 'attest', return_value=[]), \
                    patch.object(common.packets, 'REGISTRY', common.packets.REGISTRY), \
                    patch.object(common.packets, 'REFERENCE', common.packets.REFERENCE), redirect_stdout(io.StringIO()):
                publication.main()
            return json.loads((root / 'result.json').read_text())

    def test_covered_risk_without_exact_product_decision_cannot_publish(self):
        for purpose in ('rolling', 'release'):
            with self.subTest(purpose=purpose), self.assertRaisesRegex(ValueError, 'product approval required'):
                self.invoke(PublicationAPI(), purpose)

    def test_exact_current_human_product_approval_allows_both_publication_purposes(self):
        for purpose in ('rolling', 'release'):
            api = PublicationAPI()
            api.approve_product()
            with self.subTest(purpose=purpose):
                result = self.invoke(api, purpose)
                self.assertEqual(result['status'], 'covered')
                self.assertEqual(result['profiles']['maestro']['status'], 'covered')
                self.assertGreaterEqual(api.product_review_reads, 2)

    def test_another_products_approval_never_substitutes_for_exact_bytes(self):
        for purpose in ('rolling', 'release'):
            for field in ('revision', 'narHash', 'assets'):
                api = PublicationAPI()
                other = deepcopy(api.product)
                if field == 'revision':
                    other['revision'] = 'f' * 40
                elif field == 'narHash':
                    other['products']['maestro']['narHash'] = 'sha256-' + 'B' * 43 + '='
                else:
                    other['assets'] = {'different.iso': 'f' * 64}
                api.approve_product(other)
                with self.subTest(purpose=purpose, field=field), self.assertRaisesRegex(ValueError, 'product approval required'):
                    self.invoke(api, purpose)

    def test_product_review_revoked_after_initial_admission_blocks_publication(self):
        for purpose in ('rolling', 'release'):
            api = PublicationAPI()
            api.approve_product()
            api.revoke_product_on_final_check = True
            with self.subTest(purpose=purpose), self.assertRaises(common.authority.HumanDecisionRequired):
                self.invoke(api, purpose)

    def test_risk_reviewer_cannot_substitute_for_missing_product_review(self):
        for purpose in ('rolling', 'release'):
            api = PublicationAPI()
            api.approve_product()
            api.product_github.reviews = []
            with self.subTest(purpose=purpose), self.assertRaises(common.authority.HumanDecisionRequired):
                self.invoke(api, purpose)

    def test_candidate_product_schema_requires_exact_integer_type(self):
        for purpose in ('rolling', 'release'):
            for schema in (True, 1.0):
                api = PublicationAPI()
                api.approve_product()
                api.product['schema'] = schema
                with self.subTest(purpose=purpose, schema=repr(schema)), self.assertRaisesRegex(ValueError, 'Invalid immutable product identity'):
                    self.invoke(api, purpose)

    def test_product_approval_matches_canonical_identity_including_number_types(self):
        for purpose in ('rolling', 'release'):
            for schema in (True, 1.0):
                api = PublicationAPI()
                approved = dict(api.product, schema=schema)
                api.approve_product(approved)
                with self.subTest(purpose=purpose, schema=repr(schema)), self.assertRaisesRegex(ValueError, 'product approval required'):
                    self.invoke(api, purpose)

    def test_proposed_product_must_match_signed_packet_with_exact_json_types(self):
        api = PublicationAPI()
        producer = {'workflow': '.github/workflows/ci.yml', 'runId': 5, 'runAttempt': 2,
                    'repository': REPO, 'revision': SHA, 'sourceRevision': SHA}
        def fetch(reference, root, expected):
            root.mkdir(parents=True)
            (root / 'scans.json').write_text(json.dumps(api.scan))
            (root / 'product.json').write_text(json.dumps(api.product))
            return {'producer': producer}
        proposal = {'schema': 1, 'kind': 'release-product', 'payload': {
            'disposition': 'accepted', 'rationale': 'Review exact signed bytes.', 'product': deepcopy(api.product),
            'packet': dict(api.risk['payload']['packet'], producer=producer), 'supersedes': []}}
        with patch.object(common.authority, 'github_api', api), patch.object(common, 'attest', return_value=[]), \
                patch.object(reconciliation.packets, 'fetch', side_effect=fetch):
            reconciliation.validate_proposal_packet(proposal, api.policy)
            for schema in (True, 1.0):
                changed = deepcopy(proposal)
                changed['payload']['product']['schema'] = schema
                with self.subTest(schema=repr(schema)), self.assertRaisesRegex(ValueError, 'differs from authenticated exact product'):
                    reconciliation.validate_proposal_packet(changed, api.policy)


if __name__ == '__main__':
    unittest.main()
