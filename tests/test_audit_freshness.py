#!/usr/bin/env python3
import copy
import datetime as dt
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('audit_freshness', Path(__file__).parents[1] / 'ci/audit-freshness.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.sha, self.source = 'a' * 40, 'b' * 40
        self.now = dt.datetime(2026, 10, 30, 12, tzinfo=dt.timezone.utc)
        self.product = {'repository': audit.REPOSITORY, 'revision': self.source}
        self.run = {'id': 123, 'run_attempt': 2, 'head_sha': self.sha, 'head_branch': 'main',
                    'path': audit.WORKFLOW, 'event': 'push', 'repository': {'full_name': audit.REPOSITORY},
                    'head_repository': {'full_name': audit.REPOSITORY}, 'status': 'completed',
                    'conclusion': 'success', 'run_started_at': '2026-10-30T11:00:00Z',
                    'updated_at': '2026-10-30T11:20:00Z'}
        self.job = {'name': 'Repository security audit', 'head_sha': self.sha, 'run_id': 123,
                    'status': 'completed', 'conclusion': 'success',
                    'steps': [{'name': audit.STEP, 'status': 'completed', 'conclusion': 'success'}]}
        self.calls = []
        self.main_calls, self.list_calls = 0, 0
        self.change_main = self.change_run = False
        self.run_read = None
        self.comparison = {'status': 'ahead', 'merge_base_commit': {'sha': self.source}}
        self.total = 1

    def query(self, endpoint):
        self.calls.append(endpoint)
        if endpoint == 'git/ref/heads/main':
            self.main_calls += 1
            sha = 'c' * 40 if self.change_main and self.main_calls > 1 else self.sha
            return {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': sha}}
        if endpoint.startswith('actions/workflows/'):
            self.list_calls += 1
            value = copy.deepcopy(self.run)
            if self.change_run and self.list_calls > 1:
                value['run_attempt'] += 1
            return {'workflow_runs': [value]}
        if endpoint == 'actions/runs/123':
            return self.run_read or self.run
        if endpoint.endswith('/jobs?per_page=100'):
            return {'total_count': self.total, 'jobs': [self.job]}
        if endpoint.startswith('compare/'):
            return self.comparison
        self.fail(endpoint)

    def verify(self):
        return audit.verify(self.sha, self.product, self.query, self.now)

    def test_current_policy_full_audit_allows_ancestor(self):
        self.assertEqual(self.verify()['auditAttempt'], 2)
        self.assertEqual(self.main_calls, 2)
        self.assertEqual(self.list_calls, 2)

    def test_job_without_undocumented_attempt_field(self):
        self.assertNotIn('run_attempt', self.job)
        self.verify()
        self.assertIn('actions/runs/123/attempts/2/jobs?per_page=100', self.calls)

    def test_exact_source(self):
        self.product['revision'] = self.sha
        self.verify()
        self.assertFalse(any(c.startswith('compare/') for c in self.calls))

    def test_run_identity_and_failure_matrix(self):
        fields = {'id': True, 'run_attempt': 0, 'head_sha': 'd' * 40, 'head_branch': 'feature',
                  'path': '.github/workflows/ci.yml', 'event': 'pull_request',
                  'repository': {'full_name': 'attacker/repo'}, 'head_repository': {},
                  'status': 'in_progress', 'conclusion': 'failure',
                  'run_started_at': '2026-10-29T12:00:00Z', 'updated_at': '2026-10-30T13:00:00Z'}
        baseline = copy.deepcopy(self.run)
        for key, value in fields.items():
            with self.subTest(key=key):
                self.run = dict(baseline, **{key: value})
                with self.assertRaises(ValueError):
                    self.verify()

    def test_stale_no_fallback(self):
        self.run['run_started_at'] = '2026-10-29T11:59:59Z'
        with self.assertRaises(ValueError):
            self.verify()

    def test_attempt_changed(self):
        self.run_read = dict(self.run, run_attempt=3)
        with self.assertRaises(ValueError):
            self.verify()

    def test_failed_or_missing_full_step(self):
        for value in ('failure', 'skipped', None):
            self.job['steps'][0]['conclusion'] = value
            with self.assertRaises(ValueError):
                self.verify()
        self.job['steps'] = []
        with self.assertRaises(ValueError):
            self.verify()

    def test_incomplete_jobs(self):
        self.total = 101
        with self.assertRaises(ValueError):
            self.verify()

    def test_product_outside_history(self):
        for value in ({'status': 'diverged'}, {'status': 'ahead', 'merge_base_commit': {'sha': 'c' * 40}}):
            self.comparison = value
            with self.assertRaises(ValueError):
                self.verify()

    def test_race_main(self):
        self.change_main = True
        with self.assertRaises(ValueError):
            self.verify()

    def test_race_latest_run(self):
        self.change_run = True
        with self.assertRaises(ValueError):
            self.verify()

    def test_no_audit_is_not_clean(self):
        def missing(endpoint):
            return {'workflow_runs': []} if endpoint.startswith('actions/workflows/') else self.query(endpoint)
        with self.assertRaises(ValueError):
            audit.verify(self.sha, self.product, missing, self.now)

    def test_workflow_and_central_boundary_contract(self):
        root = Path(__file__).parents[1]
        workflow = (root / audit.WORKFLOW).read_text()
        self.assertIn('name: ' + audit.STEP, workflow)
        self.assertIn('ci:security-lint', workflow)
        gate = (root / 'ci/publication-gate.sh').read_text()
        self.assertLess(gate.index('AUDIT_FRESHNESS_SOURCE'), gate.index('exec xo-nixpkg-decision-publication'))
        self.assertIn('python3 "${XO_NIXPKG_HISTORY_SCAN_SOURCE:?}"', (root / 'ci/security-lint.sh').read_text())
        for leaf in ('publish.sh', 'publish-release.sh', 'tag-release.sh', 'tag-xo-release.sh', 'fetch-evidence.sh'):
            self.assertIn('xo-nixpkg-publication-gate', (root / 'ci' / leaf).read_text())


if __name__ == '__main__':
    unittest.main()
