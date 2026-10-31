"""Static source-smoke security contract; actual source realization is hosted."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]


class PublicSourceSmoke(unittest.TestCase):
    def test_no_authority_and_no_candidate_trigger(self):
        workflow = (ROOT / '.github/workflows/source-smoke.yml').read_text()
        for forbidden in ['pull_request:', 'merge_group:', 'secrets.', 'id-token:',
                          'packages: write', 'contents: write', 'actions/create-github-app-token']:
            self.assertNotIn(forbidden, workflow)
        for required in ['contents: read', 'timeout-minutes: 120', 'persist-credentials: false',
                         "github-token: ''", 'env -i HOME=', 'NIX_USER_CONF_FILES=/dev/null']:
            self.assertIn(required, workflow)

    def test_product_roots_cannot_substitute_and_scope_is_explicit(self):
        script = (ROOT / 'ci/public-source-smoke.sh').read_text()
        for required in ['for target in xen-orchestra-ce libvhdi;',
                         '--option substituters https://cache.nixos.org',
                         '--option accept-flake-config false', '--option access-tokens',
                         '--option builders', '--option sandbox true',
                         'test ! -e "$output"', '--option substitute false --realise "$drv"']:
            self.assertIn(required, script)
        self.assertLess(script.index('--realise "${dependencies[@]}"'),
                        script.index('--option substitute false --realise "$drv"'))
