# SPDX-License-Identifier: Apache-2.0
"""Execute the existing verdict truth table without Nix or candidate code."""
import itertools
import os
from pathlib import Path
import subprocess
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class GateOverhead(unittest.TestCase):
    def test_existing_verdict_truth_table(self):
        for classify, preflight, enabled, validate in itertools.product(
                ('success', 'failure'), ('success', 'failure'),
                ('true', 'false'), ('success', 'failure', 'skipped', 'cancelled')):
            expected = (classify == preflight == 'success'
                        and validate == ('success' if enabled == 'true' else 'skipped'))
            env = dict(os.environ, CLASSIFY_RESULT=classify, PREFLIGHT_RESULT=preflight,
                       VALIDATE_ENABLED=enabled, VALIDATE_RESULT=validate)
            result = subprocess.run(['bash', str(ROOT / 'ci/ci-verdict.sh')], env=env,
                                    capture_output=True, timeout=2)
            self.assertEqual(result.returncode == 0, expected,
                             (classify, preflight, enabled, validate))

    def test_gate_keeps_required_identity_dependencies_and_trusted_source(self):
        gate = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())['jobs']['gate']
        self.assertEqual(gate['name'], 'CI gate')
        self.assertEqual(gate['if'], 'always()')
        self.assertEqual(gate['needs'], ['classify', 'preflight', 'validate', 'attest-builds'])
        checkout = next(s for s in gate['steps'] if s.get('name') == 'Checkout protected verdict controller')
        self.assertEqual(checkout['with']['ref'], "${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || 'main' }}")
        self.assertFalse(checkout['with']['persist-credentials'])
        verdict = gate['steps'][-1]
        self.assertEqual(verdict['working-directory'], 'controller')
        self.assertEqual(verdict['run'], 'bash ci/ci-verdict.sh')
        self.assertFalse(any('setup-nix' in s.get('uses', '') for s in gate['steps']))

    def test_audit_keeps_daily_manual_entrypoints_only(self):
        document = yaml.safe_load((ROOT / '.github/workflows/security-audit.yml').read_text())
        events = document.get('on', document.get(True))
        self.assertEqual(set(events), {'schedule', 'workflow_dispatch'})
        self.assertEqual(events['schedule'], [{'cron': '43 4 * * *'}])
        self.assertIn("github.event_name == 'schedule'", document['jobs']['policy']['if'])


if __name__ == '__main__':
    unittest.main()
