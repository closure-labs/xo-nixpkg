# SPDX-License-Identifier: Apache-2.0
"""Keep Determinate features without implicitly enabling FlakeHub Cache."""
from pathlib import Path
import os
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
            # OIDC must remain available to later attestation steps.
            self.assertFalse(set(OIDC_ENV) & document.get('env', {}).keys())
            jobs = document.get('jobs', {'composite': document.get('runs', {})})
            for job in jobs.values():
                self.assertFalse(set(OIDC_ENV) & job.get('env', {}).keys())
                for step in job.get('steps', []):
                    uses = step.get('uses', '')
                    if uses.startswith('DeterminateSystems/determinate-nix-action@'):
                        installers += 1
                        with self.subTest(path=path.name):
                            self.assertEqual(step.get('env'), OIDC_ENV)
                            self.assertRegex(uses, r'@[a-f0-9]{40}$')
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
        self.assertEqual(steps[1]['name'], 'Verify public bootstrap cache')

    def test_effective_cache_guard_rejects_inherited_or_dynamic_caches(self):
        steps = read_yaml(ROOT / '.github/actions/setup-nix/action.yml')['runs']['steps']
        script = steps[1]['run']
        with tempfile.TemporaryDirectory() as temp:
            nix = Path(temp) / 'nix'
            # Fail if setup ever dumps the full config (which can contain tokens).
            nix.write_text('#!/bin/bash\n'
                           '[[ "$*" == "config show substituters" ]] || exit 90\n'
                           'printf "%s\\n" "$TEST_SUBSTITUTERS"\n')
            nix.chmod(0o755)
            for caches, success in [
                ('https://cache.nixos.org', True),
                ('https://cache.nixos.org https://cache.flakehub.com', False),
                ('https://edge.cache.flakehub.com', False),
                ('https://cache.nixos.org https://unexpected.example', False),
                ('', False),
            ]:
                with self.subTest(caches=caches):
                    result = subprocess.run(['bash', '-c', script], capture_output=True,
                                            text=True, env={**os.environ,
                                                           'PATH': temp + os.pathsep + os.environ['PATH'],
                                                           'TEST_SUBSTITUTERS': caches})
                    self.assertEqual(result.returncode == 0, success, result.stderr)
                    self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
