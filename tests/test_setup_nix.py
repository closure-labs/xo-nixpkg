# SPDX-License-Identifier: Apache-2.0
"""Keep Determinate features without implicitly enabling FlakeHub Cache."""
from pathlib import Path
import os
import json
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
OIDC_ENV = {
    'ACTIONS_ID_TOKEN_REQUEST_URL': '',
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN': '',
}


def read_yaml(path):
    return yaml.load(path.read_text(), Loader=yaml.BaseLoader)


class SetupNix(unittest.TestCase):
    def test_every_installer_disables_only_its_own_flakehub_login(self):
        paths = [ROOT / '.github/actions/setup-nix/action.yml',
                 *sorted((ROOT / '.github/workflows').glob('*.yml'))]
        installers = 0
        for path in paths:
            document = read_yaml(path)
            # The Node runner reinjects OIDC, so clearing it is not a login toggle.
            self.assertFalse(set(OIDC_ENV) & document.get('env', {}).keys())
            jobs = document.get('jobs', {'composite': document.get('runs', {})})
            for job in jobs.values():
                self.assertFalse(set(OIDC_ENV) & job.get('env', {}).keys())
                for step in job.get('steps', []):
                    uses = step.get('uses', '')
                    self.assertNotIn('DeterminateSystems/determinate-nix-action@', uses)
                    if uses.startswith('DeterminateSystems/nix-installer-action@'):
                        installers += 1
                        with self.subTest(path=path.name):
                            self.assertFalse(set(OIDC_ENV) & step.get('env', {}).keys())
                            following = job['steps'][job['steps'].index(step) + 1]
                            self.assertEqual(following['name'], 'Select public Nix caches')
                            canonical = read_yaml(ROOT / '.github/actions/setup-nix/action.yml')['runs']['steps'][1]
                            self.assertEqual(following['run'], canonical['run'])
                            inputs = step['with']
                            self.assertEqual(inputs['determinate'], 'false')
                            self.assertEqual(inputs['flakehub'], 'false')
                            self.assertEqual(inputs['extra-args'], '--determinate')
                            releases = {
                                '33c9ab3ef95cd57c164d9d6eb1f9a46338538d41': 'v3.21.9',
                                '9383ce2bf08796b65508822f5982f49151badc4e': 'v3.24.1',
                            }
                            self.assertEqual(inputs['source-tag'], releases[uses.split('@')[1]])
                            if 'runs-on' in job:
                                self.assertEqual(job['runs-on'], 'ubuntu-24.04')
                    else:
                        self.assertFalse(set(OIDC_ENV) & step.get('env', {}).keys())
                    self.assertNotIn('flakehub-cache-action', uses)
        self.assertGreater(installers, 0)

    def test_shared_setup_preserves_public_cache_and_hash_repair(self):
        steps = read_yaml(ROOT / '.github/actions/setup-nix/action.yml')['runs']['steps']
        config = steps[0]['with']['extra-conf']
        self.assertIn('accept-flake-config = true\n', config)
        self.assertIn('substituters = https://cache.nixos.org\n', config)
        self.assertEqual(steps[0]['with']['github-token'], '${{ inputs.github-token }}')
        flake = (ROOT / 'flake.nix').read_text()
        self.assertIn('extra-substituters = [ "https://xen-orchestra-ce.cachix.org" ];', flake)
        self.assertIn('xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E=', flake)
        self.assertIn('determinate-nixd fix hashes --auto-apply',
                      (ROOT / 'ci/fix-nix-hashes.sh').read_text())
        self.assertEqual(steps[1]['name'], 'Select public Nix caches')
        self.assertEqual(steps[2]['name'], 'Verify public bootstrap cache')

    def test_validation_bootstrap_preserves_controller_boundary(self):
        workflow = read_yaml(ROOT / '.github/workflows/ci.yml')
        shared = read_yaml(ROOT / '.github/actions/setup-nix/action.yml')['runs']['steps']
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        for name in ['classify', 'preflight', 'validate']:
            with self.subTest(job=name):
                job = workflow['jobs'][name]
                steps = job['steps']
                installer = next(s for s in steps if s.get('uses', '').startswith('DeterminateSystems/nix-installer-action@'))
                guard = next(s for s in steps if s.get('name') == 'Verify public bootstrap cache')
                self.assertEqual(installer['uses'], shared[0]['uses'])
                self.assertEqual(installer['with']['github-token'], '')
                self.assertIn('access-tokens =\n', installer['with']['extra-conf'])
                self.assertEqual(guard['run'], shared[2]['run'])
                self.assertLess(steps.index(installer), steps.index(guard))
                self.assertNotIn('write', job.get('permissions', {}).values())
                for step in steps:
                    self.assertNotIn('setup-nix', step.get('uses', ''))
                    if step.get('with', {}).get('path') == 'controller':
                        self.assertEqual(step['with']['ref'], "${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || 'main' }}")
                        self.assertEqual(step['with']['persist-credentials'], 'false')
                    if 'nix run ' in step.get('run', ''):
                        self.assertGreater(steps.index(step), steps.index(guard))
                        expected = '==' if step.get('working-directory') == 'controller' else '!='
                        self.assertIn(expected, step['if'])
        trusted = next(s for s in workflow['jobs']['validate']['steps'] if s.get('id') == 'trusted')
        self.assertEqual(trusted['working-directory'], 'controller')
        self.assertIn('ci:runtime', trusted['run'])
        self.assertIn("github.event_name != 'pull_request'", workflow['jobs']['attest-builds']['if'])

    def test_final_cache_layer_preserves_existing_settings_privately(self):
        steps = read_yaml(ROOT / '.github/actions/setup-nix/action.yml')['runs']['steps']
        script = next(s['run'] for s in steps if s.get('name') == 'Select public Nix caches')
        bash = shutil.which('bash')
        self.assertIsNotNone(bash)
        for existing in ['', 'cores = 2', 'access-tokens = github.com=DO-NOT-LOG-SECRET\nextra-substituters = https://install.determinate.systems']:
            with self.subTest(existing=bool(existing)), tempfile.TemporaryDirectory() as temp:
                envfile = Path(temp) / 'github-env'
                result = subprocess.run([bash, '-c', script], text=True, capture_output=True,
                                        env={**os.environ, 'NIX_CONFIG': existing, 'GITHUB_ENV': str(envfile)})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout + result.stderr, '')
                header, value = envfile.read_text().split('\n', 1)
                self.assertTrue(header.startswith('NIX_CONFIG<<'))
                delimiter = header.split('<<', 1)[1]
                self.assertTrue(value.endswith(delimiter + '\n'))
                config = value[:-(len(delimiter) + 1)]
                self.assertTrue(config.startswith(existing + '\n'))
                self.assertTrue(config.endswith('substituters = https://cache.nixos.org\nextra-substituters =\n\n'))
        restore = (ROOT / 'ci/validate-restore-capacity.py').read_text()
        reset = restore.split("os.environ['NIX_CONFIG'] = ", 1)[1].split('bootstrap(source, metrics)', 1)[0]
        self.assertIn('substituters = https://cache.nixos.org', reset)
        self.assertIn('extra-substituters =', reset)

    def test_effective_cache_guard_rejects_inherited_or_dynamic_caches(self):
        steps = read_yaml(ROOT / '.github/actions/setup-nix/action.yml')['runs']['steps']
        script = next(s['run'] for s in steps if s.get('name') == 'Verify public bootstrap cache')
        bash = shutil.which('bash')
        self.assertIsNotNone(bash, 'Bash must be available for the setup fixture')
        with tempfile.TemporaryDirectory() as temp:
            nix = Path(temp) / 'nix'
            # Supply typed Nix JSON, including a secret that must never be logged.
            nix.write_text(f'#!{bash}\n'
                           '[[ "$*" == "config show --json" ]] || exit 90\n'
                           'printf "%s\\n" "$TEST_SUBSTITUTERS"\n')
            nix.chmod(0o755)
            nixd = Path(temp) / 'determinate-nixd'
            nixd.write_text(f'#!{bash}\nexit 0\n')
            nixd.chmod(0o755)
            for caches, success in [
                (['https://cache.nixos.org'], True),
                (['https://cache.nixos.org/'], True),
                (['https://cache.nixos.org', 'https://cache.flakehub.com'], False),
                (['https://edge.cache.flakehub.com'], False),
                (['https://install.determinate.systems'], False),
                (['https://cache.nixos.org', 'https://user:secret@unexpected.example/token?key=secret'], False),
                (['https://cache.nixos.org/extra'], False),
                ([], False),
                ('https://cache.nixos.org', False),
                (None, False),
            ]:
                with self.subTest(caches=caches):
                    result = subprocess.run([bash, '-c', script], capture_output=True,
                                            text=True, env={**os.environ,
                                                           'PATH': temp + os.pathsep + os.environ['PATH'],
                                                           'TEST_SUBSTITUTERS': json.dumps({'substituters': {'value': caches},
                                                                                           'access-tokens': {'value': 'DO-NOT-LOG-SECRET'}}, indent=2)})
                    self.assertEqual(result.returncode == 0, success, result.stderr)
                    self.assertEqual(result.stdout, '')
                    self.assertNotIn('DO-NOT-LOG-SECRET', result.stderr)
                    self.assertNotIn('user:secret', result.stderr)
                    self.assertNotIn('key=secret', result.stderr)


if __name__ == '__main__':
    unittest.main()
