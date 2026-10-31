# SPDX-License-Identifier: Apache-2.0
"""Exact public verification material only; scanner values never reach output."""
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'ci/compare-retained-nars.py'


def public_material():
    values = re.findall(r'xen-orchestra-ce\.cachix\.org-1:([A-Za-z0-9+/]{43}=)', (ROOT/'flake.nix').read_text())
    if len(values) != 1:
        raise AssertionError('Expected one configured public verification key')
    return values[0]


class PolicyShapeTests(unittest.TestCase):
    def test_exception_is_rule_value_and_path_conjunction(self):
        config = tomllib.loads((ROOT/'.gitleaks.toml').read_text())
        self.assertTrue(config.get('extend', {}).get('useDefault') is True)
        self.assertTrue(len(config['rules']) == 1 and config['rules'][0]['id'] == 'generic-api-key')
        rows = config['rules'][0]['allowlists']
        self.assertEqual(len(rows), 2)
        row = rows[1]
        self.assertEqual(set(row), {'description', 'condition', 'regexTarget', 'paths', 'regexes'})
        self.assertEqual(row['condition'], 'AND')
        self.assertEqual(row['regexTarget'], 'secret')
        self.assertEqual(row['paths'], [r'^ci/compare-retained-nars\.py$'])
        self.assertTrue(row['regexes'] == ['^'+re.escape(public_material())+'$'], 'Exception must match the exact configured public value')
        self.assertTrue(re.fullmatch(row['paths'][0], TARGET) is not None)
        self.assertIsNone(re.fullmatch(row['paths'][0], 'ci/sub/compare-retained-nars.py'))
        self.assertIsNone(re.fullmatch(row['paths'][0], 'other/'+TARGET))

    def test_existing_ledger_exception_is_unchanged(self):
        row = tomllib.loads((ROOT/'.gitleaks.toml').read_text())['rules'][0]['allowlists'][0]
        self.assertEqual(row['condition'], 'AND')
        self.assertEqual(row['regexTarget'], 'line')
        self.assertEqual(row['paths'], [r'^automation/decisions/security/[a-f0-9]{64}\.json$'])
        self.assertEqual(row['regexes'], [r'^\n?          "key": "[a-f0-9]{64}",$'])


@unittest.skipUnless(os.environ.get('GITLEAKS_BINARY'), 'Dedicated hosted job supplies the checksum-pinned scanner')
class RealEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Fail closed if the dedicated job did not enforce physical limits.
        row = Path('/proc/self/cgroup').read_text().strip()
        if not row.startswith('0::/') or '..' in row.split('/'):
            raise AssertionError('Physical resource cgroup required')
        directory = Path('/sys/fs/cgroup')/row[3:].lstrip('/')
        memory = (directory/'memory.max').read_text().strip()
        cpu = (directory/'cpu.max').read_text().split()
        if not (memory.isdigit() and 0 < int(memory) <= 3*1024**3
                and (directory/'memory.swap.max').read_text().strip() == '0'
                and len(cpu) == 2 and all(x.isdigit() for x in cpu) and 0 < int(cpu[0]) <= int(cpu[1])):
            raise AssertionError('Enforced physical memory/CPU/no-swap controls required')

    def scan(self, path, text, config):
        def limits():
            resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
            resource.setrlimit(resource.RLIMIT_FSIZE, (128*1024, 128*1024))
        with tempfile.TemporaryDirectory(prefix='private-policy-fixture-') as temp:
            temp = Path(temp); temp.chmod(0o700); repo = temp/'repo'; repo.mkdir()
            file = repo/path; file.parent.mkdir(parents=True, exist_ok=True); file.write_text(text)
            settings = temp/'config.toml'; settings.write_text(config)
            ignore = temp/'ignore'; ignore.write_bytes(b'')
            report = temp/'report.json'
            env = {'PATH': os.environ['PATH'], 'HOME': str(temp), 'GOMAXPROCS': '1', 'GOMEMLIMIT': '256MiB'}
            for args in [('init', '-q'), ('add', '.'), ('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')]:
                result = subprocess.run(['git', *args], cwd=repo, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                self.assertEqual(result.returncode, 0, 'Isolated Git fixture failed')
            result = subprocess.run([os.environ['GITLEAKS_BINARY'], 'git', '.', '--config', str(settings),
                                     '--gitleaks-ignore-path', str(ignore), '--ignore-gitleaks-allow', '--redact=100',
                                     '--no-banner', '--log-level=error', '--exit-code=2', '--report-format=json',
                                     '--report-path', str(report), '--log-opts=--all --full-history --text --no-ext-diff --no-textconv'],
                                    cwd=repo, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=10, preexec_fn=limits, check=False)
            self.assertTrue(result.returncode in (0, 2) and report.is_file(), 'Pinned scanner fixture failed')
            self.assertLessEqual(report.stat().st_size, 128*1024)
            values = json.loads(report.read_bytes())
            if values is None:
                self.assertEqual(result.returncode, 0, 'Missing findings in failed scan')
                values = []
            self.assertTrue(isinstance(values, list) and len(values) < 100, 'Unexpected fixture finding inventory')
            # Ignore every finding value; assertions use rule/location metadata only.
            rows = [(r['RuleID'], r['File'], r['StartLine']) for r in values]
            self.assertEqual(result.returncode == 2, bool(rows))
            return rows

    def test_real_engine_preserves_other_values_paths_and_rules(self):
        value = public_material(); assignment = 'KEY = "'+value+'"\n'
        config = (ROOT/'.gitleaks.toml').read_text()
        self.assertEqual(self.scan(TARGET, assignment, config), [])
        self.assertEqual(self.scan(TARGET, assignment, '[extend]\nuseDefault = true\n'), [('generic-api-key', TARGET, 1)])
        for path in ('ci/another.py', 'ci/sub/compare-retained-nars.py', 'other/'+TARGET):
            with self.subTest(path=path):
                self.assertEqual(self.scan(path, assignment, config), [('generic-api-key', path, 1)])
        for other in ('A'+value[1:], value+'A'):
            self.assertEqual(self.scan(TARGET, 'KEY = "'+other+'"\n', config), [('generic-api-key', TARGET, 1)])
        # A synthetic marker only, never a usable private key.
        label = 'RSA '+'PRIVATE KEY'
        pem = '-'*5+'BEGIN '+label+'-'*5+'\n'+'A'*80+'\n'+'-'*5+'END '+label+'-'*5+'\n'
        self.assertEqual(self.scan(TARGET, pem, config), [('private-key', TARGET, 1)])


if __name__ == '__main__':
    unittest.main()
