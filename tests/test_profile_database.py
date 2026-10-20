#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run both parent flows with real evidence files and NAR transport containers."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ('xo-latest', 'xo-stable', 'xo-rolling', 'libvhdi')
CREDENTIALS = ('GH_TOKEN', 'GITHUB_TOKEN', 'CACHIX_AUTH_TOKEN', 'SECAUDIT_PEM',
               'REGISTRY_TOKEN', 'DECIDER_KEY', 'XO_AUTHORITY_TOKEN',
               'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_RUNTIME_TOKEN')
ANCHOR = hashlib.sha256(b'one fresh authenticated database snapshot').hexdigest()


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'ci' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


qualify = load('qualification_profile_database_test', 'qualify-products.py')
refresh = load('refresh_profile_database_test', 'refresh-products.py')


class ParentDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'qualification'
        self.environment = {'XO_NIXPKG_EVIDENCE': str(self.output),
                            'XO_NIXPKG_DISTRIBUTION_CACHE_SOURCE': str(ROOT / 'ci/distribution-cache.py'),
                            'GITHUB_RUN_ID': '345', 'GITHUB_RUN_ATTEMPT': '2'}
        self.environment.update({key: 'dummy-' + key for key in CREDENTIALS})
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, self.environment, clear=True).start()
        patch.object(subprocess, 'check_output', side_effect=self.check_output).start()
        patch.object(subprocess, 'run', side_effect=self.external_run).start()
        self.reset_observations()

    def reset_observations(self):
        self.preparations = []
        self.scans = []
        self.builds = []
        self.inventories = []
        self.realised = []
        self.transport_exports = []
        self.transport_imports = []
        self.fail_profile = None

    def no_credentials(self):
        self.assertEqual([key for key in CREDENTIALS if key in os.environ], [],
                         'Parent leaked runtime credentials into native build/scan/transport')

    @staticmethod
    def store(attribute):
        prefix = hashlib.sha256(attribute.encode()).hexdigest()[:32]
        return '/nix/store/' + prefix + '-' + attribute

    @staticmethod
    def nar(path):
        # Real transport validates the SRI shape; external Nix metadata is mocked.
        import base64
        return 'sha256-' + base64.b64encode(hashlib.sha256(path.encode()).digest()).decode()

    def check_output(self, arguments, **kwargs):
        arguments = list(arguments)
        text = kwargs.get('text', False)
        if arguments == ['git', 'rev-parse', 'HEAD']:
            result = 'a' * 40
        elif arguments[:2] == ['xo-nixpkg-security-database', 'prepare']:
            self.no_credentials()
            snapshot = Path(arguments[2])
            self.assertFalse(snapshot.exists())
            snapshot.mkdir(parents=True)
            (snapshot / 'fixture-database').write_bytes(b'fresh database bytes')
            self.preparations.append(snapshot)
            result = ANCHOR
        elif arguments[:2] == ['nix', 'build']:
            self.no_credentials()
            attribute = arguments[-1].removeprefix('.#')
            self.builds.append(attribute)
            result = self.store(attribute)
        elif arguments[:3] == ['nix', 'path-info', '--json']:
            self.no_credentials()
            result = json.dumps({path: {'path': path, 'narHash': self.nar(path)}
                                 for path in arguments[3:]})
        elif arguments[:3] == ['nix', 'copy', '--to']:
            self.no_credentials()
            destination = Path(unquote(urlparse(arguments[3]).path))
            destination.mkdir()
            (destination / 'nix-cache-info').write_text('StoreDir: /nix/store\n')
            (destination / 'fixture.nar.zst').write_bytes(b'bounded external Nix export fixture')
            self.transport_exports.append(arguments[4:])
            result = ''
        elif arguments[:3] == ['nix', 'copy', '--from']:
            self.no_credentials()
            source = Path(unquote(urlparse(arguments[3]).path))
            self.assertEqual((source / 'fixture.nar.zst').read_bytes(), b'bounded external Nix export fixture')
            self.transport_imports.append(arguments[5:])
            result = ''
        else:
            raise AssertionError('Unexpected external check_output: ' + repr(arguments))
        return result if text else result.encode()

    def external_run(self, arguments, **kwargs):
        arguments = list(arguments)
        self.assertTrue(kwargs.get('check'))
        if arguments[:2] == ['xo-nixpkg-build-reuse', 'restore']:
            # Only the identity-only fetch helper may receive the initial read credential.
            self.assertEqual(os.environ['GH_TOKEN'], 'dummy-GH_TOKEN')
            Path(arguments[arguments.index('--output')+1]).write_text('{"status":"miss"}\n')
        elif arguments[0] == 'xo-nixpkg-security-inventory':
            self.no_credentials()
            profile = arguments[arguments.index('--profile')+1]
            directory = Path(arguments[arguments.index('--output')+1])
            directory.mkdir()
            root = arguments[arguments.index('--root')+1]
            self.inventories.append((profile, directory, root))
            for filename in ('runtime.cdx.json', 'closure.json', 'derivations.json', 'inventory.json'):
                (directory / filename).write_text(json.dumps({'profile': profile, 'root': root, 'file': filename}))
        elif arguments[0] == 'xo-nixpkg-security-native-scan':
            self.no_credentials()
            source, output = map(Path, arguments[1:3])
            self.assertEqual(source, output)
            profile = source.name
            snapshot = Path(arguments[arguments.index('--database')+1])
            anchor = arguments[arguments.index('--database-receipt-sha256')+1]
            self.assertEqual((snapshot / 'fixture-database').read_bytes(), b'fresh database bytes')
            self.scans.append((profile, source, snapshot, anchor))
            if profile == self.fail_profile:
                raise subprocess.CalledProcessError(2, arguments)
            (output / 'scan.json').write_text(json.dumps({'healthy': True, 'findings': [], 'profile': profile}))
        elif arguments[:2] == ['cp', '-R']:
            self.no_credentials()
            destination = Path(arguments[3])
            destination.mkdir()
            (destination / 'assertion.json').write_text(json.dumps({'source': arguments[2]}))
        elif arguments[:2] == ['nix-store', '--realise']:
            self.no_credentials()
            self.realised.append(arguments[2])
        else:
            raise AssertionError('Unexpected external run: ' + repr(arguments))
        return subprocess.CompletedProcess(arguments, 0)

    def assert_snapshot_lifecycle(self, expected_profiles):
        self.assertEqual(len(self.preparations), 1)
        self.assertEqual([item[0] for item in self.scans], list(expected_profiles))
        self.assertEqual({item[2] for item in self.scans}, set(self.preparations))
        self.assertEqual({item[3] for item in self.scans}, {ANCHOR})
        self.assertFalse(self.preparations[0].exists(), 'Database snapshot survived parent exit')
        self.assertFalse(self.preparations[0].parent.exists(), 'Database temporary directory survived parent exit')

    def assert_profile_subjects(self, scans, product):
        self.assertEqual(set(scans['profiles']), set(PROFILES))
        self.assertEqual(len({record['storePath'] for record in product['products'].values()}), 4)
        for profile in PROFILES:
            observation = scans['profiles'][profile]
            self.assertEqual(observation['profile'], profile)
            subjects = [product['products'][profile], *(
                {'storePath': extra['storePath'], 'narHash': extra['narHash']}
                for extra in product['roots'].values() if extra['profile'] == profile)]
            self.assertEqual(observation['subjects'][0], product['products'][profile])
            self.assertEqual({item['storePath']: item['narHash'] for item in observation['subjects']},
                             {item['storePath']: item['narHash'] for item in subjects})
            self.assertEqual(len(observation['subjects']), len(subjects))
            self.assertEqual(len(subjects), 3 if profile == 'xo-latest' else 1 if profile == 'libvhdi' else 2)

    def seed_refresh(self):
        qualify.main()
        source = self.output
        product_before = (source / 'product.json').read_bytes()
        scan_before = (source / 'scans.json').read_bytes()
        self.reset_observations()
        self.output = self.root / 'refresh'
        os.environ.update(self.environment)
        os.environ.update(XO_NIXPKG_RESCAN_SOURCE=str(source), XO_NIXPKG_EVIDENCE=str(self.output))
        return source, product_before, scan_before

    def test_qualification_prepares_one_database_for_four_independent_profiles(self):
        qualify.main()
        self.assert_snapshot_lifecycle(PROFILES)
        self.assertEqual(len({directory for _, directory, _ in self.inventories}), 4)
        self.assertEqual(len(self.transport_exports), 1)
        product = json.loads((self.output / 'product.json').read_text())
        scans = json.loads((self.output / 'scans.json').read_text())
        self.assert_profile_subjects(scans, product)
        self.assertEqual(set(self.transport_exports[0]),
                         {root['storePath'] for root in product['products'].values()} |
                         {root['storePath'] for root in product['roots'].values()})
        self.assertEqual(len(list(self.output.glob('handoff-*.json'))), 4)
        self.assertTrue(list(self.output.glob('distribution-cache.tar.part-*')))

    def test_qualification_scan_failure_cleans_database_and_never_publishes_aggregate(self):
        self.fail_profile = 'xo-rolling'
        with self.assertRaises(subprocess.CalledProcessError): qualify.main()
        self.assert_snapshot_lifecycle(PROFILES[:3])
        self.assertFalse((self.output / 'product.json').exists())
        self.assertFalse((self.output / 'scans.json').exists())
        self.assertFalse(list(self.output.glob('handoff-*.json')))
        self.assertFalse(list(self.output.glob('distribution-cache.tar.part-*')))
        self.assertEqual(self.transport_exports, [])
        self.assertNotIn('libvhdi', self.builds)

    def test_refresh_prepares_one_database_and_reuses_exact_immutable_subjects(self):
        source, product_before, scan_before = self.seed_refresh()
        refresh.main()
        # Product dictionaries serialize in key order, unlike qualification's build order.
        expected = tuple(json.loads(product_before)['products'])
        self.assert_snapshot_lifecycle(expected)
        self.assertEqual(self.builds, [], 'Refreshing retained products rebuilt source')
        self.assertEqual(self.inventories, [], 'Refreshing retained products regenerated inventory')
        self.assertEqual(self.transport_exports, [])
        self.assertEqual(len(self.transport_imports), 1)
        self.assertEqual((self.output / 'product.json').read_bytes(), product_before)
        self.assertEqual((source / 'product.json').read_bytes(), product_before)
        self.assertEqual((source / 'scans.json').read_bytes(), scan_before)
        scans = json.loads((self.output / 'scans.json').read_text())
        self.assert_profile_subjects(scans, json.loads(product_before))
        self.assertEqual(set(self.realised), {subject['storePath'] for observation in scans['profiles'].values()
                                            for subject in observation['subjects']})
        self.assertEqual(len(list(self.output.glob('handoff-*.json'))), 4)

    def test_refresh_scan_failure_cleans_database_and_removes_old_success_aggregates(self):
        source, product_before, scan_before = self.seed_refresh()
        expected = tuple(json.loads(product_before)['products'])
        self.fail_profile = expected[1]
        with self.assertRaises(subprocess.CalledProcessError): refresh.main()
        self.assert_snapshot_lifecycle(expected[:2])
        self.assertFalse((self.output / 'scans.json').exists())
        self.assertFalse(list(self.output.glob('handoff-*.json')))
        self.assertEqual((self.output / 'product.json').read_bytes(), product_before)
        self.assertEqual((source / 'product.json').read_bytes(), product_before)
        self.assertEqual((source / 'scans.json').read_bytes(), scan_before)
        self.assertEqual(self.builds, [])
        self.assertEqual(self.transport_exports, [])


if __name__ == '__main__':
    unittest.main()
