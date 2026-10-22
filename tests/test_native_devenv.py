# SPDX-License-Identifier: Apache-2.0
"""Public startup and the local prompt must not resolve runtime credentials."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOKEN = 'fixture-token-never-project-into-nix'
PUBLIC = {'XO_AUTHORITY_WAKEUPS_VALIDATED', 'XO_NIXPKG_AUDIT_NIX_BIN'}


def yaml(path):
    return json.loads(subprocess.check_output(['yq', '-o=json', '.', str(path)], text=True))


class NativeDevenvTests(unittest.TestCase):
    def test_cli_toolchain_pin_avoids_the_cold_ifd_wrapper(self):
        revision = 'c8f90650c15282fa8656a041bfbbd2403997a9a7'
        config = yaml(ROOT / 'devenv.yaml')
        self.assertEqual(config['inputs']['devenv']['inputs']['nixpkgs']['url'],
                         'github:NixOS/nixpkgs/' + revision)
        for name in ('flake.lock', 'devenv.lock'):
            lock = json.loads((ROOT / name).read_text())
            nodes = lock['nodes']
            tool = nodes[nodes['root']['inputs']['devenv']]
            source = nodes[tool['inputs']['nixpkgs']]
            self.assertEqual(source['locked']['owner'], 'NixOS')
            self.assertEqual(source['locked']['repo'], 'nixpkgs')
            self.assertEqual(source['locked']['rev'], revision)
            self.assertEqual(source['locked']['narHash'], 'sha256-pRGOQSClnXNI2iLUG6DYpsGvYcuw0drOutVZFTJNw90=')
            self.assertNotIn('inputs', source)
            self.assertNotIn('flake', source)
            self.assertNotEqual(nodes['root']['inputs']['nixpkgs'], tool['inputs']['nixpkgs'])
            self.assertFalse(any(node.get('locked', {}).get('repo') == 'devenv-nixpkgs'
                                 for node in nodes.values()))

    def test_default_local_and_hosted_configuration_contract(self):
        base = yaml(ROOT / 'devenv.yaml')
        local = yaml(ROOT / 'devenv.local.yaml.example')
        self.assertEqual(base['secretspec'], {'enable': False, 'cachix_auth_token': False})
        self.assertEqual(local['secretspec'], {
            'enable': True, 'provider': 'keyring', 'profile': 'development',
            'cachix_auth_token': 'CACHIX_XO_DEVENV_TOKEN'})
        self.assertEqual(base['require_version'], '>= 2.4')
        self.assertEqual(base['inputs']['devenv']['url'], 'github:cachix/devenv/v2.4.0')
        locks = [json.loads((ROOT / name).read_text()) for name in ('flake.lock', 'devenv.lock')]
        for lock in locks:
            node = lock['nodes'][lock['nodes']['root']['inputs']['devenv']]
            self.assertEqual(node['locked']['rev'], 'b904dcb51fe48c30db250038241507f60752f222')
        manifest = tomllib.loads((ROOT / 'secretspec.toml').read_text())
        self.assertEqual(set(manifest['profiles']['default']), PUBLIC)
        self.assertEqual(manifest['profiles']['development'], {})
        self.assertNotIn('CACHIX_XO_DEVENV_TOKEN', manifest['profiles']['runtime'])
        self.assertIn('devenv.local.yaml', (ROOT / '.gitignore').read_text().splitlines())
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            self.assertNotIn('cachix.push', path.read_text())

    def test_real_secret_resolution_does_not_inherit_credentials_into_development(self):
        executable = os.environ.get('SECRETSPEC_BIN')
        if not executable:
            self.skipTest('Native policy check supplies the pinned SecretSpec executable')
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / 'secretspec.toml'
            manifest.write_bytes((ROOT / 'secretspec.toml').read_bytes())
            env = {'PATH': os.environ['PATH'], 'XDG_DATA_HOME': directory, 'XDG_CONFIG_HOME': directory,
                   'XDG_STATE_HOME': directory, 'SECRETSPEC_REASON': 'Test isolated dummy secrets',
                   'GH_TOKEN': TOKEN, 'CACHIX_AUTH_TOKEN': TOKEN, 'DECIDER_KEY': TOKEN,
                   'CACHIX_XO_DEVENV_TOKEN': TOKEN}
            result = subprocess.run([executable, '--file', str(manifest), 'export',
                                     '--provider', 'env', '--profile', 'development', '--format', 'json'],
                                    env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, 'Native development profile must resolve without credentials')
            value = json.loads(result.stdout)
            self.assertTrue(set(value) <= PUBLIC)
            self.assertNotIn(TOKEN, result.stdout)
            self.assertNotIn(TOKEN, result.stderr)
            # Explicit runtime remains available and resolves the same dummy token.
            result = subprocess.run([executable, '--file', str(manifest), 'export',
                                     '--provider', 'env', '--profile', 'github-publish', '--format', 'json'],
                                    env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, 'Explicit publication contract remains valid')
            self.assertEqual(json.loads(result.stdout)['CACHIX_AUTH_TOKEN'], TOKEN)


if __name__ == '__main__':
    unittest.main()
