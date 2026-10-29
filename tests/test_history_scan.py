"""Full-history batching must never turn missing coverage into a passing gate."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('history_scan', ROOT / 'ci/history-scan.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class HistoryScan(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.commit('clean.txt', 'safe\n')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.DEVNULL).decode().strip()

    def commit(self, name, content):
        (self.root / name).write_text(content)
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def fake_run(self, calls, code=0):
        original = mod.operations.run
        def execute(args, **kwargs):
            if args[0] == 'fixture-scanner':
                self.assertEqual(kwargs['stdout'], subprocess.DEVNULL)
                self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
                self.assertIn('--redact', args)
                self.assertIn('--no-banner', args)
                self.assertIn('--no-walk=unsorted --full-history --diff-filter=tuxdb', args[-1])
                calls.extend(args[-1].split()[3:])
                return subprocess.CompletedProcess(args, code)
            return original(args, **kwargs)
        return execute

    def test_all_refs_tags_detached_head_and_ancestors_scanned_once(self):
        self.git('checkout', '-qb', 'other')
        secret = self.commit('removed.txt', 'historical fixture\n')
        self.git('tag', 'retained-tag')
        self.git('checkout', '-q', 'main')
        self.git('branch', '-D', 'other')
        self.commit('clean.txt', 'next\n')
        self.git('checkout', '--detach', '-q')
        self.commit('detached.txt', 'detached\n')
        expected = set(self.git('rev-list', '--all').splitlines())
        calls = []
        with patch.object(mod, 'BATCH_SIZE', 1), patch.object(mod.operations, 'run', side_effect=self.fake_run(calls)):
            result = mod.scan(self.root, scanner='fixture-scanner')
        self.assertEqual(set(calls), expected)
        self.assertEqual(len(calls), len(expected))
        self.assertIn(secret, calls)
        self.assertEqual(result['commits'], len(expected))

    def test_worker_inherits_overall_deadline(self):
        original = mod.operations.run
        observed = []
        def execute(args, **kwargs):
            if args[0] == 'fixture-scanner':
                observed.append(mod.operations.remaining(mod.BATCH_TIMEOUT))
                return subprocess.CompletedProcess(args, 0)
            return original(args, **kwargs)
        with patch.object(mod, 'TOTAL_TIMEOUT', 10), patch.object(mod.operations, 'run', side_effect=execute):
            mod.scan(self.root, scanner='fixture-scanner')
        self.assertTrue(observed)
        self.assertTrue(all(0 < value <= 10 for value in observed))

    def test_inventory_limit_blocks_before_scan(self):
        calls = []
        with patch.object(mod, 'MAX_COMMITS', 0), patch.object(mod.operations, 'run', side_effect=self.fake_run(calls)), self.assertRaises(ValueError):
            mod.scan(self.root, scanner='fixture-scanner')
        self.assertEqual(calls, [])

    def test_linked_detached_worktree_head_is_included(self):
        linked = self.root / 'linked'
        self.git('worktree', 'add', '--detach', str(linked))
        (linked / 'only-linked.txt').write_text('detached worktree history\n')
        subprocess.run(['git', '-C', str(linked), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(linked), 'commit', '-qm', 'linked'], check=True)
        expected = set(self.git('rev-list', '--all').splitlines())
        calls = []
        with patch.object(mod.operations, 'run', side_effect=self.fake_run(calls)):
            mod.scan(self.root, scanner='fixture-scanner')
        self.assertEqual(set(calls), expected)
        self.assertEqual(len(expected), 2)

    def test_timeout_hierarchy_fits_native_history_job(self):
        self.assertLessEqual(mod.BATCH_TIMEOUT, mod.TOTAL_TIMEOUT)
        self.assertEqual(mod.TOTAL_TIMEOUT, 1200)
        self.assertLess(mod.TOTAL_TIMEOUT + mod.operations.KILL_GRACE, 1260)
        self.assertLess(1260, 30 * 60)

    def test_failed_batch_diagnostics_are_bounded_fixed_metadata(self):
        output = io.StringIO()
        with patch.object(mod.operations, 'run', side_effect=self.fake_run([], 1)), contextlib.redirect_stdout(output), self.assertRaises(ValueError):
            mod.scan(self.root, scanner='fixture-scanner')
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(set(rows[0]), {'schema', 'stage', 'status', 'batch', 'commits', 'reason', 'seconds'})
        self.assertEqual(rows[0]['reason'], 'findings-or-scanner-error')
        self.assertEqual(rows[0]['batch'], 0)
        self.assertEqual(rows[0]['commits'], 1)

    def test_failed_scanner_blocks(self):
        with patch.object(mod.operations, 'run', side_effect=self.fake_run([], 1)), self.assertRaises(ValueError):
            mod.scan(self.root, scanner='fixture-scanner')

    def test_timeout_blocks(self):
        original = mod.operations.run
        def execute(args, **kwargs):
            if args[0] == 'fixture-scanner':
                raise subprocess.TimeoutExpired(args, 1)
            return original(args, **kwargs)
        with patch.object(mod.operations, 'run', side_effect=execute), self.assertRaises(subprocess.TimeoutExpired):
            mod.scan(self.root, scanner='fixture-scanner')

    def test_ref_change_during_scan_blocks(self):
        execute = self.fake_run([])
        def mutate(args, **kwargs):
            result = execute(args, **kwargs)
            if args[0] == 'fixture-scanner':
                self.git('tag', 'changed')
            return result
        with patch.object(mod.operations, 'run', side_effect=mutate), self.assertRaises(ValueError):
            mod.scan(self.root, scanner='fixture-scanner')

    def test_shallow_history_blocks_before_scan(self):
        (self.root / '.git/shallow').write_text(self.git('rev-parse', 'HEAD') + '\n')
        calls = []
        with patch.object(mod.operations, 'run', side_effect=self.fake_run(calls)), self.assertRaises(ValueError):
            mod.scan(self.root, scanner='fixture-scanner')
        self.assertEqual(calls, [])

    @unittest.skipUnless(shutil.which('gitleaks'), 'native Gitleaks is unavailable')
    def test_native_scanner_matches_full_history_with_secret_removed_renamed_and_merged(self):
        self.commit('.gitleaks.toml', '[extend]\nuseDefault = true\n[[rules]]\nid="fixture"\ndescription="fixture"\nregex="TEST_SECRET_[A-Z]{12}"\n')
        self.git('checkout', '-qb', 'side')
        self.commit('original.txt', 'TEST_SECRET_ABCDEFGHIJKL\n')
        self.git('mv', 'original.txt', 'renamed.txt')
        self.git('commit', '-qm', 'rename')
        self.git('rm', 'renamed.txt')
        self.git('commit', '-qm', 'delete')
        self.git('checkout', '-q', 'main')
        self.commit('main.txt', 'clean\n')
        self.git('merge', '--no-ff', '-qm', 'merge', 'side')
        original = subprocess.run(['gitleaks', 'git', '--redact', '--no-banner'], cwd=self.root,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        self.assertEqual(original.returncode, 1)
        with patch.object(mod, 'BATCH_SIZE', 1), self.assertRaises(ValueError):
            mod.scan(self.root)

    @unittest.skipUnless(shutil.which('gitleaks'), 'native Gitleaks is unavailable')
    def test_large_ledger_does_not_hide_neighbor_secret(self):
        self.commit('.gitleaks.toml', '[extend]\nuseDefault = true\n[[rules]]\nid="fixture"\ndescription="fixture"\nregex="TEST_SECRET_[A-Z]{12}"\n')
        self.commit('ledger.json', 'safe generated evidence\n' * 50000 + 'TEST_SECRET_ABCDEFGHIJKL\n')
        with self.assertRaises(ValueError):
            mod.scan(self.root)

    @unittest.skipUnless(shutil.which('gitleaks'), 'native Gitleaks is unavailable')
    def test_native_clean_root_merge_rename_and_binary_pass(self):
        self.git('checkout', '-qb', 'side')
        self.commit('side.txt', 'safe side\n')
        self.git('checkout', '-q', 'main')
        self.commit('main.txt', 'safe main\n')
        self.git('merge', '--no-ff', '-qm', 'merge', 'side')
        self.git('mv', 'side.txt', 'renamed.txt')
        (self.root / 'binary').write_bytes(bytes(range(256)))
        self.git('add', '.')
        self.git('commit', '-qm', 'rename and binary')
        with patch.object(mod, 'BATCH_SIZE', 1):
            self.assertEqual(mod.scan(self.root)['status'], 'success')


if __name__ == '__main__':
    unittest.main()
