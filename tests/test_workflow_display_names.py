"""Display-name cleanup keeps event consumers and protected check names aligned."""
from pathlib import Path
import re
import unittest
ROOT = Path(__file__).resolve().parents[1]
W = ROOT / '.github/workflows'


class WorkflowDisplayNames(unittest.TestCase):
    def test_names_are_unique_and_live_wakeups_exist(self):
        names = [re.search(r'^name: (.+)$', p.read_text(), re.M)[1] for p in W.glob('*.yml')]
        self.assertEqual(len(names), len(set(names)))
        for p in W.glob('*.yml'):
            text = p.read_text()
            if 'workflow_run:' not in text:
                continue
            block = text.split('    workflows:', 1)[1].split('    types:', 1)[0]
            listeners = (block.strip()[1:-1].split(',') if block.strip().startswith('[')
                         else re.findall(r'^      - (.+)$', block, re.M))
            for listener in listeners:
                self.assertIn(listener.strip(), names, p.name)

    def test_protected_job_names_and_scheduler_formats_stay_stable(self):
        self.assertIn('name: CI gate', (W / 'ci.yml').read_text())
        self.assertIn('name: Repository security audit', (W / 'repository-secret-scan.yml').read_text())
        self.assertIn("CHECK_NAME = 'Maintainer decision authority'",
                      (ROOT / 'ci/decisions/check.py').read_text())
        for needle, path in [('Refresh qualification {0} attempt {1}', 'qualification.yml'),
                             ('Publish {0} qualification {1} attempt {2}', 'publish.yml')]:
            self.assertIn(needle, (W / path).read_text())

    def test_exact_signal_relay_template_tracks_display_name(self):
        import sys
        sys.path.insert(0, str(ROOT / 'ci/decisions'))
        import signal_relay
        signal_relay.validate((W / 'decision-events.yml').read_text())
