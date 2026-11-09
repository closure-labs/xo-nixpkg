# SPDX-License-Identifier: Apache-2.0
"""Event ownership prevents redundant controllers without losing recovery."""
from pathlib import Path
from types import SimpleNamespace
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

    def test_queue_skips_validation_that_cannot_enqueue_a_new_candidate(self):
        value, _ = workflow('queue-automation.yml')
        condition = value['jobs']['enqueue']['if'].replace('&&', ' and ').replace('||', ' or ')
        for workflow_name in ['Validate packages', 'Verify merge approval', 'Relay update reviews']:
            for source in ['pull_request', 'merge_group', 'schedule', 'workflow_dispatch', 'workflow_run']:
                for conclusion in ['success', 'failure', 'cancelled', 'skipped']:
                    for validated in ['true', 'false']:
                        github = SimpleNamespace(repository='closure-labs/xo-nixpkg', ref='refs/heads/main',
                            event_name='workflow_run', event=SimpleNamespace(
                                repository=SimpleNamespace(default_branch='main'),
                                workflow_run=SimpleNamespace(name=workflow_name, event=source, conclusion=conclusion)))
                        variables = SimpleNamespace(XO_AUTHORITY_WAKEUPS_VALIDATED=validated)
                        scope = {'github': github, 'vars': variables, 'format': lambda pattern, value: pattern.format(value)}
                        expected = (conclusion == 'success'
                            and (workflow_name != 'Validate packages' or source == 'pull_request')
                            and (workflow_name != 'Relay update reviews' or validated != 'true'))
                        with self.subTest(workflow=workflow_name, source=source, conclusion=conclusion, validated=validated):
                            self.assertEqual(bool(eval(condition, {'__builtins__': {}}, scope)), expected)
        for event_name in ['schedule', 'workflow_dispatch']:
            for repository in ['closure-labs/xo-nixpkg', 'other/fork']:
                for ref in ['refs/heads/main', 'refs/pull/1/merge']:
                    github = SimpleNamespace(repository=repository, ref=ref, event_name=event_name,
                        event=SimpleNamespace(repository=SimpleNamespace(default_branch='main')))
                    self.assertEqual(bool(eval(condition, {'__builtins__': {}},
                        {'github': github, 'format': lambda pattern, value: pattern.format(value)})),
                        repository == 'closure-labs/xo-nixpkg' and ref == 'refs/heads/main')

    def test_reconcile_still_observes_review_qualification_and_merged_decisions(self):
        _, events = workflow('security-reconcile.yml')
        self.assertEqual(events['workflow_run']['workflows'], ['Qualify release products', 'Verify merge approval'])
        self.assertEqual(events['push']['paths'], ['automation/decisions/**'])
        self.assertIn('schedule', events)
        self.assertIn('workflow_dispatch', events)


if __name__ == '__main__':
    unittest.main()
