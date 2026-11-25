# SPDX-License-Identifier: Apache-2.0
"""Post-publication verification is pinned to a successful immutable attempt."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci/decisions'))
import native_approvals as native
from test_native_approvals import cfg, request


class PublishedConsumer(unittest.TestCase):
    def setUp(self):
        self.cfg, self.request = cfg(), request()
        self.revision = 'e' * 40
        self.run = {'id': 123, 'run_attempt': 2, 'head_sha': self.revision, 'head_branch': 'main',
                    'path': '.github/workflows/publish.yml', 'status': 'completed', 'conclusion': 'success',
                    'event': 'push', 'repository': {'full_name': native.REPOSITORY},
                    'head_repository': {'full_name': native.REPOSITORY}}
        self.jobs = {'total_count': 2, 'jobs': [
            {'name': name, 'head_sha': self.revision, 'status': 'completed', 'conclusion': 'success'}
            for name in ('Validate the native-reviewed product', 'Publish reviewed immutable product')]}

    def api(self, endpoint):
        if endpoint.endswith('/actions/runs/123/attempts/2'):
            return self.run
        if endpoint.endswith('/attempts/2/jobs?per_page=100'):
            return self.jobs
        if endpoint.endswith('/git/ref/heads/main'):
            return {'object': {'sha': 'f' * 40}}
        if '/compare/' in endpoint:
            return {'status': 'ahead'}
        self.fail('Unexpected consumer API read: ' + endpoint)

    def select(self):
        def document(api, repository, path, revision):
            self.assertEqual(revision, self.revision)
            return self.cfg if path == native.POLICY else self.request
        with patch.object(native.github, 'document_at', side_effect=document):
            return native.published_request(self.cfg, 123, 2, self.api)

    def test_exact_successful_published_request_survives_main_advancing(self):
        self.assertEqual(self.select(), (self.revision, self.request))

    def test_wrong_workflow_fork_attempt_or_failed_run_never_selects(self):
        for key, bad in [('run_attempt', 1), ('path', '.github/workflows/qualification.yml'),
                         ('conclusion', 'failure'), ('head_branch', 'other'), ('event', 'pull_request'),
                         ('head_repository', {'full_name': 'other/fork'})]:
            original = deepcopy(self.run)
            self.run[key] = bad
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'completed publication'):
                self.select()
            self.run = original

    def test_skipped_failed_missing_or_duplicate_publish_jobs_block(self):
        original = deepcopy(self.jobs)
        for mutation in [lambda j: j['jobs'][1].update(conclusion='skipped'),
                         lambda j: j['jobs'][1].update(head_sha='a' * 40),
                         lambda j: j['jobs'].pop(),
                         lambda j: j['jobs'].__setitem__(1, deepcopy(j['jobs'][0]))]:
            self.jobs = deepcopy(original)
            mutation(self.jobs)
            with self.assertRaises(ValueError):
                self.select()

    def test_post_publish_trigger_executes_only_immutable_protected_consumer_code(self):
        document = yaml.safe_load((ROOT / '.github/workflows/consumer-probe.yml').read_text())
        events = document.get('on', document.get(True))
        self.assertEqual(events['workflow_run']['workflows'], ['Publish reviewed products'])
        self.assertIn('schedule', events)
        self.assertIn('workflow_dispatch', events)
        job = document['jobs']['consumer']
        self.assertIn("conclusion == 'success'", job['if'])
        self.assertEqual(job['steps'][0]['with']['ref'], '${{ github.workflow_sha }}')
        probe = next(step for step in job['steps'] if 'CONSUMER_PUBLICATION_RUN' in step.get('env', {}))
        self.assertEqual(probe['env']['CONSUMER_PUBLICATION_ATTEMPT'], '${{ github.event.workflow_run.run_attempt }}')
        self.assertTrue(all(value == 'read' for value in document['permissions'].values()))


if __name__ == '__main__':
    unittest.main()
