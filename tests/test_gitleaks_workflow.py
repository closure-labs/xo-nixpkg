"""Small Git-graph/exit-status fixtures; never execute a scanner on XPS."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/repository-secret-scan.yml'

def gate_module():
    spec = importlib.util.spec_from_file_location('incoming_gate_tests', ROOT / 'ci/audit-freshness.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

GATE = gate_module()

def scan_script():
    text = WORKFLOW.read_text().split('      - name: Scan complete introduced commit range\n', 1)[1].split('        run: |\n', 1)[1]
    rows = []
    for line in text.splitlines():
        if line and not line.startswith('            ') and not line.startswith('          '):
            break
        rows.append(line[10:])
    return '\n'.join(rows) + '\n'

class RangeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'candidate'
        self.repo.mkdir()
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
        self.git('init', '-q', '-b', 'main')
        self.commit('base.txt', 'pre-existing-marker\n')
        self.base = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-q', '-b', 'side')
        self.commit('side.txt', 'side-introduced-then-deleted-marker\n')
        self.side = self.git('rev-parse', 'HEAD')
        self.git('rm', '-q', 'side.txt')
        self.git('commit', '-qm', 'remove side fixture')
        self.git('checkout', '-q', 'main')
        self.commit('main.txt', 'main-introduced-marker\n')
        self.git('merge', '--no-ff', '--no-commit', 'side')
        self.commit('merge-only.txt', 'merge-only-resolution-marker\n')
        self.head = self.git('rev-parse', 'HEAD')
        (self.root / 'controller').mkdir()
        (self.root / 'controller/.gitleaks.toml').write_bytes((ROOT / '.gitleaks.toml').read_bytes())
        self.runtime = self.root / 'runtime'
        (self.runtime / 'gitleaks').mkdir(parents=True)
        binary = self.runtime / 'gitleaks/gitleaks'
        binary.write_text('#!' + sys.executable + '\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ["ARG_LOG"]).write_text(json.dumps(sys.argv[1:]))\nprint("DO-NOT-EXPOSE-FIXTURE-PAYLOAD")\nsys.exit(int(os.environ.get("SCANNER_EXIT","0")))\n')
        binary.chmod(0o755)

    def git(self, *args):
        return subprocess.check_output(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', *args], cwd=self.repo, env=self.env, stderr=subprocess.DEVNULL, text=True).strip()

    def commit(self, name, text):
        (self.repo / name).write_text(text)
        self.git('add', name)
        self.git('commit', '-qm', 'synthetic fixture')

    def run_scan(self, **values):
        env = dict(self.env, EVENT_NAME='pull_request', BASE_SHA=self.base, HEAD_SHA=self.head,
                   RUNNER_TEMP=str(self.runtime), GITHUB_WORKSPACE=str(self.root), ARG_LOG=str(self.root / 'args.json'))
        env.update(values)
        return subprocess.run(['bash', '-c', scan_script()], cwd=self.repo, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_complete_graph_and_merge_only_content(self):
        result = self.run_scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads((self.root / 'args.json').read_text())
        opts = next(a.split('=', 1)[1] for a in args if a.startswith('--log-opts='))
        self.assertNotIn('--first-parent ', opts)
        self.assertNotIn('--no-merges', opts)
        patch = self.git('log', '-p', '-U0', *opts.split())
        for marker in ['side-introduced-then-deleted-marker', 'merge-only-resolution-marker', 'main-introduced-marker']:
            self.assertIn('+' + marker, patch)
        self.assertNotIn('+pre-existing-marker', patch)
        self.assertIn(self.side, patch)
        self.assertNotIn('DO-NOT-EXPOSE', result.stdout + result.stderr)
        self.assertIn('--redact=100', args)
        self.assertFalse(any(a.startswith('--report') or a.startswith('--baseline') for a in args))
        self.assertEqual(self.run_scan(EVENT_NAME='merge_group').returncode, 0)

    def test_missing_bad_equal_and_wrong_checkout_fail_before_scanner(self):
        for values in [{'BASE_SHA': ''}, {'BASE_SHA': '1' * 40}, {'HEAD_SHA': 'not-a-sha'},
                       {'BASE_SHA': self.head}, {'HEAD_SHA': self.base}, {'EVENT_NAME': 'workflow_run'}]:
            with self.subTest(values=values):
                result = self.run_scan(**values)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'args.json').exists())

    def test_diverged_pr_base_is_valid_but_queue_base_must_be_ancestor(self):
        self.git('checkout', '-q', '-b', 'new-base', self.base)
        self.commit('new-base.txt', 'new base data\n')
        diverged = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-q', 'main')
        self.assertEqual(self.run_scan(BASE_SHA=diverged).returncode, 0)
        self.assertNotEqual(self.run_scan(BASE_SHA=diverged, EVENT_NAME='merge_group').returncode, 0)

    def test_shallow_checkout_fails(self):
        (self.repo / '.git/shallow').write_text(self.base + '\n')
        self.assertNotEqual(self.run_scan().returncode, 0)
        self.assertFalse((self.root / 'args.json').exists())

    def test_findings_errors_and_timeouts_never_pass_or_leak(self):
        for status in [1, 2, 124, 137]:
            result = self.run_scan(SCANNER_EXIT=str(status))
            self.assertEqual(result.returncode, status)
            self.assertNotIn('DO-NOT-EXPOSE', result.stdout + result.stderr)

class ProofAPI:
    def __init__(self):
        self.run = {'id': 7, 'run_attempt': 2, 'head_sha': 'b' * 40, 'event': 'merge_group',
            'head_branch': 'gh-readonly-queue/main/pr-10-' + 'a' * 40,
            'path': '.github/workflows/repository-secret-scan.yml', 'status': 'completed', 'conclusion': 'success',
            'repository': {'id': GATE.native.REPO_ID}, 'head_repository': {'id': GATE.native.REPO_ID}}
        self.job = {'id': 9, 'name': 'Repository security audit', 'head_sha': 'b' * 40, 'status': 'completed', 'conclusion': 'success'}
        self.owner = 15368
        self.count = 1
        self.changed_source = False
        self.calls = []
    def get(self, path):
        self.calls.append(path)
        if '/workflows/' in path and '/runs?' in path:
            return {'total_count': self.count, 'workflow_runs': [{'id': 7}]}
        if path.endswith('/actions/runs/7'):
            return copy.deepcopy(self.run)
        if '/git/commits/' in path:
            return {'parents': [{'sha': 'a' * 40}, {'sha': 'c' * 40}]}
        if '/contents/' in path:
            file = ROOT / ('.gitleaks.toml' if '/contents/.gitleaks.toml?' in path else '.github/workflows/repository-secret-scan.yml')
            raw = file.read_bytes() + (b'changed' if self.changed_source else b'')
            return {'encoding': 'base64', 'size': len(raw), 'content': base64.b64encode(raw).decode()}
        if '/attempts/2/jobs?' in path:
            return {'total_count': 1, 'jobs': [copy.deepcopy(self.job)]}
        if path.endswith('/check-runs/9'):
            return {'app': {'id': self.owner}, 'name': 'Repository security audit', 'head_sha': 'b' * 40, 'conclusion': 'success'}
        raise AssertionError('Unexpected proof request')

class PublicationProofTests(unittest.TestCase):
    def test_success_binds_run_attempt_and_exact_range(self):
        api = ProofAPI()
        proof = GATE.incoming_check(api, 'b' * 40)
        self.assertEqual(proof, {'runId': 7, 'runAttempt': 2, 'base': 'a' * 40, 'head': 'b' * 40})
        self.assertTrue(any('/attempts/2/jobs?' in p for p in api.calls))

    def test_failed_foreign_history_wrong_head_and_incomplete_runs_block(self):
        for key, value in [('conclusion', 'failure'), ('event', 'schedule'), ('status', 'in_progress'),
                           ('head_sha', 'd' * 40), ('repository', {'id': 1}), ('run_attempt', 0)]:
            api = ProofAPI(); api.run[key] = value
            with self.subTest(key=key), self.assertRaises(GATE.native.Blocked):
                GATE.incoming_check(api, 'b' * 40)

    def test_wrong_owner_failed_job_changed_policy_and_cap_block(self):
        for change in ['owner', 'job', 'source', 'cap', 'range']:
            api = ProofAPI()
            if change == 'owner': api.owner = 5384448
            if change == 'job': api.job['conclusion'] = 'failure'
            if change == 'source': api.changed_source = True
            if change == 'cap': api.count = 100
            if change == 'range': api.run['head_branch'] = 'gh-readonly-queue/main/pr-10-' + 'c' * 40
            with self.subTest(change=change), self.assertRaises(GATE.native.Blocked):
                GATE.incoming_check(api, 'b' * 40)

    def verify_with_race(self, change):
        api = ProofAPI()
        binding = GATE.native.policy_binding()
        product = {'repository': GATE.native.REPO, 'revision': 'b' * 40, 'repositorySecretPolicy': binding}
        scans = {'repositorySecretPolicy': binding}
        original_get = api.get
        selected = {'id': 7}

        def get(path):
            if '/workflows/' in path and '/runs?' in path:
                return {'total_count': 1, 'workflow_runs': [{'id': selected['id']}]}
            if path.endswith('/actions/runs/8'):
                return copy.deepcopy(api.run)
            if '/actions/runs/8/attempts/2/jobs?' in path or '/actions/runs/7/attempts/3/jobs?' in path:
                return {'total_count': 1, 'jobs': [copy.deepcopy(api.job)]}
            return original_get(path)

        api.get = get

        def observe(*args, **kwargs):
            if change == 'rerun-in-progress':
                api.run.update(run_attempt=3, status='in_progress', conclusion=None)
            elif change == 'new-latest-success':
                selected['id'] = 8
                api.run['id'] = 8
            elif change == 'new-successful-attempt':
                api.run['run_attempt'] = 3
            elif change == 'job-failed':
                api.job['conclusion'] = 'failure'
            elif change == 'owner-changed':
                api.owner = 5384448
            return {'status': 'observed', 'openAlertCount': 0}

        with patch.object(GATE.native, 'observe', side_effect=observe):
            return GATE.verify('a' * 40, product, scans, api, metadata_api=api)

    def test_publication_final_reread_preserves_same_successful_proof(self):
        result = self.verify_with_race(None)
        self.assertEqual(result['incomingScan']['runId'], 7)
        self.assertEqual(result['incomingScan']['runAttempt'], 2)

    def test_publication_final_reread_rejects_concurrent_rerun_or_new_latest_run(self):
        for change in ['rerun-in-progress', 'new-latest-success', 'new-successful-attempt', 'job-failed', 'owner-changed']:
            with self.subTest(change=change), self.assertRaises(GATE.native.Blocked):
                self.verify_with_race(change)

    def test_workflow_is_read_only_and_history_is_separate_visible_debt(self):
        text = WORKFLOW.read_text()
        self.assertIn('pull_request:', text)
        self.assertIn('merge_group:', text)
        self.assertIn('Repository historical audit (nonblocking debt)', text)
        for absent in ['secrets.', 'write\n', 'continue-on-error:', 'upload-artifact', 'pull_request_target:', 'workflow_run:', '--baseline-path', '--max-target-megabytes']:
            self.assertNotIn(absent, text)
        self.assertIn('551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb', text)
        self.assertFalse((ROOT / '.github/workflows/native-secret-observation.yml').exists())
        self.assertFalse(hasattr(GATE.native, 'publish_check'))

if __name__ == '__main__': unittest.main()
