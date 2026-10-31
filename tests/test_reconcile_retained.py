# SPDX-License-Identifier: Apache-2.0
"""Exercise the scheduling leaf with actual Bash/jq and isolated service fakes."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'closure-labs/xo-nixpkg'


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.calls = self.root / 'calls.jsonl'
        self.producer = {'id': 123, 'run_attempt': 2, 'repository': {'full_name': REPOSITORY},
                         'head_repository': {'full_name': REPOSITORY}, 'head_sha': 'a' * 40,
                         'head_branch': 'main', 'path': '.github/workflows/qualification.yml',
                         'event': 'push', 'status': 'completed', 'conclusion': 'success',
                         'created_at': '2026-10-20T00:00:00Z',
                         'updated_at': '2026-10-20T00:00:00Z'}
        self.fixture = {'producer': self.producer, 'publish': [], 'qualification': [],
                        'expiresAt': '2099-01-01T00:00:00Z', 'admitted': True}
        fake = '#!' + sys.executable + '''
import json, os, pathlib, sys
from urllib.parse import parse_qs, urlsplit
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with open(os.environ['FIXTURE_CALLS'], 'a') as stream:
    stream.write(json.dumps([name, *args]) + '\\n')
fixture = json.loads(pathlib.Path(os.environ['FIXTURE_DATA']).read_text())
if name == 'gh' and args[0] == 'api':
    endpoint = args[1]
    if fixture.get('api_failure') and fixture['api_failure'] in endpoint:
        sys.exit(1)
    if '/actions/runs/' in endpoint:
        print(json.dumps(fixture['producer']))
    elif 'qualification.yml/runs' in endpoint and 'status=success' in endpoint:
        print(json.dumps({'workflow_runs': [] if fixture.get('empty') else [fixture['producer']]}))
    else:
        key = 'publish' if 'publish.yml/runs' in endpoint else 'qualification'
        pages = fixture.get(key + '_pages')
        page = int(parse_qs(urlsplit(endpoint).query).get('page', ['1'])[0])
        records = pages[page - 1] if pages and page <= len(pages) else fixture[key]
        print(json.dumps({'workflow_runs': records}))
elif name == 'xo-nixpkg-inspect-qualification':
    if fixture.get('inspection_failure'):
        sys.exit(2)
    print(json.dumps({'schema': 1, 'status': fixture.get('observation_state', 'expired' if fixture['expiresAt'] < '2026' else 'current')}))
elif name == 'gh' and args[:2] == ['run', 'download']:
    if fixture.get('expired_artifact'):
        sys.exit(1)
    directory = pathlib.Path(args[args.index('--dir') + 1])
    directory.mkdir(parents=True)
    producer = fixture['producer']
    scan = {'expiresAt': fixture['expiresAt'], 'producer': {'runId': producer['id'],
            'runAttempt': fixture.get('evidence_attempt', producer['run_attempt'])}}
    (directory / 'scans.json').write_text(json.dumps(scan))
    (directory / 'product.json').write_text('{"revision":"exact-product"}')
elif name == 'xo-nixpkg-decision-publication' and not fixture['admitted']:
    sys.exit(2)
'''
        for name in ('gh', 'oras', 'xo-nixpkg-decision-reconcile', 'xo-nixpkg-decision-publication',
                     'xo-nixpkg-publication-gate', 'xo-nixpkg-inspect-qualification'):
            executable = self.bin / name
            executable.write_text(fake)
            executable.chmod(0o755)
        self.data = self.root / 'fixture.json'

    def run_scheduler(self, **environment):
        self.data.write_text(json.dumps(self.fixture))
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                   GITHUB_REPOSITORY=REPOSITORY, GITHUB_ACTOR='fixture',
                   REGISTRY_TOKEN='fixture-registry-token', FIXTURE_CALLS=str(self.calls),
                   FIXTURE_DATA=str(self.data))
        env.pop('QUALIFICATION_RUN', None)
        env.pop('QUALIFICATION_ATTEMPT', None)
        env.update(environment)
        result = subprocess.run(['bash', str(ROOT / 'ci/reconcile-retained.sh')],
                                cwd=ROOT, env=env, text=True, capture_output=True)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []
        return result, calls

    def workflow(self, workflow='publish', *, run=123, attempt=2, status='in_progress',
                 conclusion=None, purpose='release'):
        result = copy.deepcopy(self.producer)
        result.update(path=f'.github/workflows/{workflow}.yml', event='workflow_dispatch',
                      status=status, conclusion=conclusion, created_at='2026-10-20T00:00:01Z')
        result['display_title'] = (f'Publish {purpose} qualification {run} attempt {attempt}'
                                   if workflow == 'publish' else f'Refresh qualification {run} attempt {attempt}')
        return result

    @staticmethod
    def dispatches(calls):
        return [call for call in calls if call[:3] == ['gh', 'workflow', 'run']]

    def test_authenticated_obsolete_policy_waits_without_refresh_or_publication(self):
        for published in [False, True]:
            self.calls.unlink(missing_ok=True)
            self.fixture.update(observation_state='awaiting-current-evidence',
                publish=[self.workflow(status='completed', conclusion='success')] if published else [])
            result, calls = self.run_scheduler()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('awaiting-current-evidence', result.stdout)
            self.assertEqual(self.dispatches(calls), [])
            self.assertFalse(any(c[0].startswith('xo-nixpkg-decision') for c in calls))

    def test_policy_authentication_failure_never_becomes_wait_or_dispatch(self):
        self.fixture['inspection_failure'] = True
        result, calls = self.run_scheduler()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.dispatches(calls), [])
        self.assertFalse(any(c[0].startswith('xo-nixpkg-decision') for c in calls))

    def test_explicit_trigger_identity_avoids_latest_success_discovery(self):
        result, calls = self.run_scheduler(QUALIFICATION_RUN='123', QUALIFICATION_ATTEMPT='2')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any('status=success' in str(call) for call in calls))
        self.assertTrue(any('/actions/runs/123' in str(call) for call in calls))

    def test_changed_or_malformed_trigger_attempt_fails_before_effects(self):
        for attempt in ('1', '3', '2;false'):
            with self.subTest(attempt=attempt):
                self.calls.unlink(missing_ok=True)
                result, calls = self.run_scheduler(QUALIFICATION_RUN='123', QUALIFICATION_ATTEMPT=attempt)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call[:3] == ['gh', 'run', 'download'] for call in calls))
                self.assertEqual(self.dispatches(calls), [])

    def test_default_selects_one_successful_product_and_preserves_both_decisions(self):
        result, calls = self.run_scheduler()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len([c for c in calls if c[:3] == ['gh', 'run', 'download']]), 1)
        discovery = next(c[2] for c in calls if c[:2] == ['gh', 'api'] and 'status=success' in c[2])
        self.assertIn('per_page=1', discovery)
        decisions = [c for c in calls if c[0] == 'xo-nixpkg-decision-reconcile']
        self.assertEqual([c[-1] for c in decisions], ['security-findings', 'release-product'])
        dispatch = self.dispatches(calls)
        self.assertEqual(len(dispatch), 1)
        self.assertIn('qualification_run=123', dispatch[0])
        self.assertIn('qualification_attempt=2', dispatch[0])
        self.assertIn('purpose=release', dispatch[0])

    def test_active_and_completed_exact_publication_do_not_reconcile_or_redispatch(self):
        for status, conclusion in [('in_progress', None), ('pending', None), ('completed', 'success')]:
            with self.subTest(status=status):
                self.calls.unlink(missing_ok=True)
                self.fixture['publish'] = [self.workflow(status=status, conclusion=conclusion)]
                result, calls = self.run_scheduler()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(self.dispatches(calls))
                self.assertFalse(any(c[0].startswith('xo-nixpkg-decision') for c in calls))

    def test_other_attempt_run_purpose_and_failed_publication_do_not_suppress(self):
        variants = [self.workflow(attempt=1, status='completed', conclusion='success'),
                    self.workflow(run=122), self.workflow(purpose='rolling'),
                    self.workflow(status='completed', conclusion='failure')]
        for variant in variants:
            with self.subTest(variant=variant):
                self.calls.unlink(missing_ok=True)
                self.fixture['publish'] = [variant]
                result, calls = self.run_scheduler()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(self.dispatches(calls)), 1)

    def test_fork_workflow_and_wrong_branch_cannot_suppress(self):
        for field, value in [('head_branch', 'feature'), ('path', '.github/workflows/other.yml'),
                             ('head_repository', {'full_name': 'attacker/fork'})]:
            self.calls.unlink(missing_ok=True)
            record = self.workflow()
            record[field] = value
            self.fixture['publish'] = [record]
            result, calls = self.run_scheduler()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(self.dispatches(calls)), 1)

    def test_expired_scan_dispatches_one_exact_refresh_even_after_completed_publication(self):
        self.fixture.update(expiresAt='2000-01-01T00:00:00Z',
                            publish=[self.workflow(status='completed', conclusion='success')])
        result, calls = self.run_scheduler()
        self.assertEqual(result.returncode, 0, result.stderr)
        dispatch = self.dispatches(calls)
        self.assertEqual(len(dispatch), 1)
        self.assertEqual(dispatch[0][3], 'qualification.yml')
        self.assertIn('qualification_attempt=2', dispatch[0])
        self.assertFalse(any(c[0].startswith('xo-nixpkg-decision') for c in calls))

    def test_active_refresh_suppresses_only_matching_attempt(self):
        self.fixture.update(expiresAt='2000-01-01T00:00:00Z',
                            qualification=[self.workflow('qualification')])
        result, calls = self.run_scheduler()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.dispatches(calls))
        self.calls.unlink()
        self.fixture['qualification'][0] = self.workflow('qualification', attempt=1)
        result, calls = self.run_scheduler()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.dispatches(calls)), 1)

    def test_manual_history_and_no_successful_candidate(self):
        self.fixture['producer']['id'] = 100
        result, calls = self.run_scheduler(QUALIFICATION_RUN='100')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(c[:3] == ['gh', 'api', f'repos/{REPOSITORY}/actions/runs/100'] for c in calls))
        self.assertFalse(any('status=success' in c[-1] for c in calls))
        self.calls.unlink()
        self.fixture['empty'] = True
        result, calls = self.run_scheduler()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.dispatches(calls))
        self.assertIn('awaiting successful qualification; no evidence authority claimed', result.stdout)
        self.assertFalse(any(c[0].startswith('xo-nixpkg-') for c in calls))

    def test_discovery_failure_and_invalid_inputs_fail_before_side_effects(self):
        for changes, environment in [({'api_failure': 'qualification.yml/runs'}, {}),
                                     ({}, {'QUALIFICATION_RUN': '123;false'}),
                                     ({}, {'QUALIFICATION_RUN': '124'}),
                                     ({'evidence_attempt': 1}, {})]:
            self.calls.unlink(missing_ok=True)
            original = copy.deepcopy(self.fixture)
            self.fixture.update(changes)
            result, calls = self.run_scheduler(**environment)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(self.dispatches(calls))
            self.assertFalse(any(c[0].startswith('xo-nixpkg-decision') for c in calls))
            self.fixture = original

    def test_dispatch_lookup_failure_cannot_be_treated_as_no_active_work(self):
        for expired, failure in [(False, 'publish.yml/runs'), (True, 'workflow_dispatch')]:
            self.calls.unlink(missing_ok=True)
            self.fixture.update(api_failure=failure, expiresAt='2000-01-01T00:00:00Z' if expired else '2099-01-01T00:00:00Z')
            result, calls = self.run_scheduler()
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(self.dispatches(calls))

    def test_matching_work_on_later_page_is_not_redispatched(self):
        self.fixture['publish_pages'] = [[self.workflow(run=122)] * 100, [self.workflow()]]
        result, calls = self.run_scheduler()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.dispatches(calls))
        self.assertTrue(any('page=2' in c[-1] for c in calls))

    def test_lookup_overflow_is_an_error_without_dispatch(self):
        self.fixture['publish'] = [self.workflow(run=122)] * 100
        result, calls = self.run_scheduler()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('exceeded 1000', result.stderr)
        self.assertFalse(self.dispatches(calls))

    def test_completed_refresh_on_first_page_does_not_hide_active_refresh_on_second(self):
        self.fixture.update(expiresAt='2000-01-01T00:00:00Z', qualification_pages=[
            [self.workflow('qualification', status='completed', conclusion='success')]
            + [self.workflow('qualification', run=122)] * 99,
            [self.workflow('qualification')]])
        result, calls = self.run_scheduler()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.dispatches(calls))
        self.assertTrue(any('page=2' in c[-1] for c in calls))

    def test_missing_admission_never_dispatches_publication(self):
        self.fixture['admitted'] = False
        result, calls = self.run_scheduler()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.dispatches(calls))
        self.assertTrue(any(c[0] == 'xo-nixpkg-decision-publication' for c in calls))

    def test_fetch_binds_request_and_evidence_to_the_exact_successful_attempt(self):
        for requested, evidence_attempt, expected in [('2', 2, 0), ('', 2, 0), ('1', 2, 1),
                                                      ('2', 1, 1), ('invalid', 2, 1)]:
            with self.subTest(requested=requested, evidence_attempt=evidence_attempt):
                self.calls.unlink(missing_ok=True)
                self.fixture['evidence_attempt'] = evidence_attempt
                self.data.write_text(json.dumps(self.fixture))
                output = self.root / f'evidence-{requested or "current"}-{evidence_attempt}'
                env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                           GITHUB_REPOSITORY=REPOSITORY, QUALIFICATION_RUN='123',
                           QUALIFICATION_ATTEMPT=requested, XO_NIXPKG_EVIDENCE=str(output),
                           FIXTURE_CALLS=str(self.calls), FIXTURE_DATA=str(self.data))
                result = subprocess.run(['bash', str(ROOT / 'ci/fetch-evidence.sh')],
                                        cwd=ROOT, env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, expected == 0, result.stderr)
                calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
                gates = [call for call in calls if call[0] == 'xo-nixpkg-publication-gate']
                self.assertEqual(len(gates), 1 if expected == 0 else 0)


if __name__ == '__main__':
    unittest.main()
