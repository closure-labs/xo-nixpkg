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
from unittest.mock import patch, mock_open

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

    def test_receipt_has_full_inventory_and_no_authority_or_reuse_claim(self):
        self.git('tag', 'sensitive-ref-label')
        with patch.object(mod.operations, 'run', side_effect=self.fake_run([])):
            result = mod.scan(self.root, scanner='fixture-scanner')
        receipt = result['receipt']
        self.assertIs(result['authorityClaim'], False)
        self.assertIs(result['reuseEligible'], False)
        self.assertEqual(receipt['commitIds'], sorted(self.git('rev-list', '--all').splitlines()))
        self.assertFalse(receipt['authorityClaim'])
        self.assertFalse(receipt['reuseEligible'])
        self.assertFalse(receipt['scanner']['productionPinned'])
        self.assertEqual(receipt['policySha256'], {'.gitleaks.toml': None, '.gitleaksignore': None})
        self.assertEqual(len(receipt['helperSha256']), 64)
        self.assertTrue(receipt['gitVersion'].startswith('git version '))
        self.assertNotIn('sensitive-ref-label', json.dumps(receipt))
        self.assertTrue(all(set(row) == {'object', 'nameSha256'} for row in receipt['refs']))

    def test_policy_mutation_during_scan_blocks(self):
        execute = self.fake_run([])
        def mutate(args, **kwargs):
            result = execute(args, **kwargs)
            if args[0] == 'fixture-scanner':
                (self.root / '.gitleaksignore').write_text('changed-policy')
            return result
        with patch.object(mod.operations, 'run', side_effect=mutate), self.assertRaises(ValueError):
            mod.scan(self.root, scanner='fixture-scanner')

    def test_executable_mutation_during_scan_blocks(self):
        scanner = self.root / 'scanner'
        scanner.write_text('#!/bin/sh\nexit 0\n')
        scanner.chmod(0o755)
        original = mod.operations.run
        def mutate(args, **kwargs):
            if args[0] == str(scanner):
                scanner.write_text('#!/bin/sh\n# changed\nexit 0\n')
                return subprocess.CompletedProcess(args, 0)
            return original(args, **kwargs)
        with patch.object(mod.operations, 'run', side_effect=mutate), self.assertRaises(ValueError):
            mod.scan(self.root, scanner=str(scanner))

    def test_symlink_policy_is_rejected(self):
        (self.root / 'policy').write_text('safe')
        (self.root / '.gitleaksignore').symlink_to('policy')
        with self.assertRaises(ValueError):
            mod.scan(self.root, scanner='fixture-scanner')

    def test_receipt_limit_fails_closed(self):
        with patch.object(mod, 'MAX_RECEIPT_BYTES', 1), \
                patch.object(mod.operations, 'run', side_effect=self.fake_run([])), self.assertRaises(ValueError):
            mod.scan(self.root, scanner='fixture-scanner')

    def test_main_requires_pinned_metadata_before_scanning(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(mod, 'scan') as scan, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(mod.main(), 1)
        scan.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['status'], 'blocked')

    def test_production_identity_validation(self):
        scanner = '/nix/store/' + 'a' * 32 + '-gitleaks-8.30.1/bin/gitleaks'
        identity = {'schema': 1, 'name': 'gitleaks', 'version': '8.30.1',
                    'regexpEngine': 'go-stdlib', 'executable': scanner,
                    'unexpected': 'do-not-echo'}
        environment = {'XO_NIXPKG_SECRET_SCANNER': scanner,
                       'XO_NIXPKG_SECRET_SCANNER_IDENTITY': '/nix/store/' + 'b' * 32 + '-identity.json'}
        with patch.object(Path, 'is_file', return_value=True), \
                patch.object(Path, 'is_symlink', return_value=False), patch.object(os, 'access', return_value=True), \
                patch.object(Path, 'open', mock_open(read_data=json.dumps(identity).encode())):
            actual, metadata = mod.production_scanner(environment)
            self.assertEqual(actual, scanner)
            self.assertNotIn('unexpected', metadata)
            self.assertEqual(metadata['metadataSha256'], mod.hashlib.sha256(json.dumps(identity).encode()).hexdigest())
            with patch.object(Path, 'open', mock_open(read_data=b'x' * 4097)), self.assertRaises(ValueError):
                mod.production_scanner(environment)
            with self.assertRaises(ValueError):
                mod.production_scanner(dict(environment, XO_NIXPKG_SECRET_SCANNER_IDENTITY=json.dumps(identity)))
            for field, value in [('version', '8.29.0'), ('regexpEngine', 're2'),
                                 ('executable', '/tmp/gitleaks'), ('schema', 2)]:
                bad = json.dumps(dict(identity, **{field: value})).encode()
                with self.subTest(field=field), patch.object(Path, 'open', mock_open(read_data=bad)), self.assertRaises(ValueError):
                    mod.production_scanner(environment)
            with self.assertRaises(ValueError):
                mod.production_scanner(dict(environment, GITLEAKS_CONFIG='/tmp/config'))
        with self.assertRaises(ValueError):
            mod.production_scanner(dict(environment, XO_NIXPKG_SECRET_SCANNER='/tmp/gitleaks'))

    def test_production_rejects_external_extension_or_invalid_toml(self):
        scanner = self.root / 'scanner'
        scanner.write_text('#!/bin/sh\nexit 0\n')
        scanner.chmod(0o755)
        for content in ('[extend]\npath = "elsewhere.toml"\n',
                        '[ExTeNd]\nPaTh = "elsewhere.toml"\n', 'invalid TOML'):
            (self.root / '.gitleaks.toml').write_text(content)
            with self.subTest(content=content), self.assertRaises(ValueError):
                mod.scan(self.root, scanner=str(scanner), scanner_identity={'fixture': True})

    def test_executable_and_policy_hashes_are_recorded(self):
        scanner = self.root / 'scanner'
        scanner.write_text('#!/bin/sh\nexit 0\n')
        scanner.chmod(0o755)
        (self.root / '.gitleaks.toml').write_text('[extend]\nuseDefault = true\n')
        result = mod.scan(self.root, scanner=str(scanner))
        receipt = result['receipt']
        self.assertEqual(receipt['scanner']['executableSha256'], mod.file_digest(scanner))
        self.assertEqual(receipt['policySha256']['.gitleaks.toml'],
                         mod.file_digest(self.root / '.gitleaks.toml'))

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
