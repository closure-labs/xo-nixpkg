# SPDX-License-Identifier: Apache-2.0
"""Queue checks must reject new findings, incomplete scans and unrelated runs."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from urllib.parse import parse_qs, urlsplit
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci/decisions'))
import codeql_findings as gate

BASE, HEAD = 'a' * 40, 'b' * 40
REF = 'refs/heads/gh-readonly-queue/main/pr-123-' + BASE
UPLOAD = '12345678-1234-1234-1234-123456789abc'


def analysis(candidate=True, count=0):
    return {'id': 2 if candidate else 1, 'commit_sha': HEAD if candidate else BASE,
            'ref': REF if candidate else 'refs/heads/main', 'category': '/language:python',
            'analysis_key': gate.WORKFLOW + ':analyze-protected', 'tool': {'name': 'CodeQL'},
            'error': '', 'warning': '', 'results_count': count, 'rules_count': 43, 'sarif_id': UPLOAD}


def sarif(record, findings=()):
    rules, results = [], []
    for number, level, score in findings:
        name = 'fixture/rule-' + str(number)
        rules.append({'id': name, 'defaultConfiguration': {'level': 'warning'},
                      'properties': {} if score is None else {'security-severity': score, 'tags': ['security']}})
        results.append({'ruleId': name, 'level': level, 'properties': {'github/alertNumber': number}})
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'CodeQL'}, 'extensions': [{'name': 'fixture-queries', 'rules': rules}]},
        'automationDetails': {'id': '/language:python/'},
        'versionControlProvenance': [{'repositoryUri': 'https://github.com/' + gate.native.REPOSITORY,
                                     'branch': record['ref'], 'revisionId': record['commit_sha']}],
        'results': results}]}


class QueueFindings(unittest.TestCase):
    def setUp(self):
        self.candidate, self.base = analysis(), analysis(False)
        self.candidate_results, self.base_results = [], []
        self.event = {'merge_group': {'head_sha': HEAD, 'base_sha': BASE, 'head_ref': REF,
                                      'base_ref': 'refs/heads/main'}}
        self.run = {'id': 123, 'run_attempt': 2, 'path': gate.WORKFLOW, 'event': 'merge_group',
                    'head_sha': HEAD, 'head_branch': REF.removeprefix('refs/heads/'),
                    'repository': {'full_name': gate.native.REPOSITORY},
                    'head_repository': {'full_name': gate.native.REPOSITORY}}

    def api(self, endpoint):
        if endpoint.endswith('/actions/runs/123/attempts/2'):
            return self.run
        if endpoint.endswith('/git/ref/heads/main'):
            return {'object': {'sha': BASE}}
        if '/compare/' in endpoint:
            return {'status': 'identical'}
        query = parse_qs(urlsplit(endpoint).query)
        self.assertIn('/code-scanning/analyses?', endpoint)
        if query.get('sarif_id') == [UPLOAD]:
            return [self.candidate]
        return [self.base]

    def read(self, record):
        findings = self.candidate_results if record['id'] == 2 else self.base_results
        return sarif(record, findings)

    def verify(self):
        self.candidate['results_count'] = len(self.candidate_results)
        self.base['results_count'] = len(self.base_results)
        return gate.verify('python', UPLOAD, self.event, 123, 2, self.api, self.read)

    def test_clean_scan_and_nonblocking_results_pass(self):
        self.assertEqual(self.verify()['status'], 'verified')
        self.candidate_results = [(1, 'warning', '6.9'), (2, 'note', None)]
        self.assertEqual(self.verify()['newBlockingFindings'], 0)

    def test_errors_high_and_critical_findings_block_even_with_equal_counts(self):
        for level, score in [('error', None), ('warning', '7'), ('warning', '9.8')]:
            self.base_results = [(1, level, score)]
            self.candidate_results = [(2, level, score)]
            with self.subTest(level=level, score=score), self.assertRaisesRegex(ValueError, 'New blocking'):
                self.verify()

    def test_existing_base_findings_pass_but_severity_increase_blocks(self):
        self.candidate_results = self.base_results = [(1, 'warning', '7')]
        self.assertEqual(self.verify()['status'], 'verified')
        self.candidate_results = [(1, 'warning', '9.8')]
        with self.assertRaisesRegex(ValueError, 'New blocking'):
            self.verify()

    def test_wrong_run_attempt_repository_or_merge_sha_is_rejected(self):
        for key, bad in [('run_attempt', 1), ('event', 'pull_request'), ('head_sha', BASE),
                         ('path', '.github/workflows/other.yml'), ('head_branch', 'main'),
                         ('head_repository', {'full_name': 'other/fork'})]:
            original = deepcopy(self.run)
            self.run[key] = bad
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'run or attempt'):
                self.verify()
            self.run = original

    def test_missing_failed_empty_or_unrelated_analysis_blocks(self):
        for key, bad in [('error', 'analysis failed'), ('warning', 'incomplete extraction'), ('rules_count', 0),
                         ('results_count', True), ('ref', 'refs/heads/main'), ('commit_sha', BASE),
                         ('category', '/language:actions'), ('sarif_id', 'different')]:
            original = deepcopy(self.candidate)
            self.candidate[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                gate.verify('python', UPLOAD, self.event, 123, 2, self.api, self.read)
            self.candidate = original

    def test_missing_exact_base_does_not_fall_back_to_another_commit(self):
        self.base['commit_sha'] = 'c' * 40
        with self.assertRaisesRegex(ValueError, 'Exact CodeQL analysis unavailable'):
            self.verify()

    def test_malformed_or_incomplete_sarif_cannot_look_clean(self):
        record = analysis(count=1)
        good = sarif(record, [(1, 'warning', '8.1')])
        mutations = [lambda d: d['runs'][0].pop('results'),
                     lambda d: d['runs'][0]['results'].clear(),
                     lambda d: d['runs'][0]['results'][0]['properties'].clear(),
                     lambda d: d['runs'][0]['versionControlProvenance'][0].update(revisionId=BASE),
                     lambda d: d['runs'][0]['tool']['extensions'][0]['rules'][0]['properties'].update({'security-severity': 'NaN'}),
                     lambda d: d['runs'][0]['tool']['extensions'][0]['rules'][0]['properties'].pop('security-severity')]
        for mutation in mutations:
            document = deepcopy(good)
            mutation(document)
            with self.assertRaises(ValueError):
                gate.blocking_findings(document, record)

    def test_each_required_language_job_enforces_its_own_processed_upload(self):
        workflow = yaml.safe_load((ROOT / gate.WORKFLOW).read_text())
        job = workflow['jobs']['analyze-protected']
        self.assertEqual(job['strategy']['matrix']['language'], list(gate.LANGUAGES))
        analyze = next(s for s in job['steps'] if s.get('id') == 'analysis')
        self.assertIs(analyze['with']['wait-for-processing'], True)
        step = job['steps'][-1]
        self.assertEqual(step['if'], "github.event_name == 'merge_group'")
        self.assertEqual(step['run'], 'python3 ci/check-codeql-findings.py')
        self.assertEqual(step['env']['CODEQL_UPLOAD'], '${{ steps.analysis.outputs.sarif-id }}')
        self.assertNotIn('security-events', workflow['jobs']['analyze']['permissions'])


if __name__ == '__main__':
    unittest.main()
