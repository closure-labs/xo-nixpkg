# SPDX-License-Identifier: Apache-2.0
"""Event ownership prevents redundant controllers without losing recovery."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
W = ROOT / '.github/workflows'


def workflow(name):
    value = yaml.safe_load((W / name).read_text())
    return value, value.get('on', value.get(True))


class ControllerWakeups(unittest.TestCase):
    def test_admission_has_direct_held_run_and_review_wakeups(self):
        value, events = workflow('ci-admission.yml')
        self.assertEqual(events['workflow_run']['workflows'], [
            'Validate packages', 'CodeQL analysis', 'Scan repository secrets', 'Collect PR and queue events'])
        self.assertEqual(events['schedule'], [{'cron': '17 * * * *'}])
        self.assertIn('workflow_dispatch', events)
        condition = value['jobs']['admit']['if']
        self.assertIn("conclusion == 'action_required'", condition)
        self.assertIn("event == 'pull_request_review'", condition)
        self.assertNotIn('Verify merge approval', condition)
        self.assertIn('ref: main', (W / 'ci-admission.yml').read_text())

    def test_queue_waits_for_candidate_validation_or_authority(self):
        _, events = workflow('queue-automation.yml')
        self.assertEqual(events['workflow_run']['workflows'], [
            'Validate packages', 'Verify merge approval', 'Relay update reviews'])
        self.assertIn('schedule', events)
        self.assertIn('workflow_dispatch', events)

    def test_reconcile_still_observes_review_qualification_and_merged_decisions(self):
        _, events = workflow('security-reconcile.yml')
        self.assertEqual(events['workflow_run']['workflows'], ['Qualify release products', 'Verify merge approval'])
        self.assertEqual(events['push']['paths'], ['automation/decisions/**'])
        self.assertIn('schedule', events)
        self.assertIn('workflow_dispatch', events)


if __name__ == '__main__':
    unittest.main()
