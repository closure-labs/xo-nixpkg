"""Organization-only maintenance is not ordinary public candidate validation."""
from pathlib import Path
import re
import unittest
ROOT = Path(__file__).resolve().parents[1]


class MaintenanceScope(unittest.TestCase):
    def test_all_organization_maintenance_jobs_have_repository_guard(self):
        files = ['qualification.yml', 'prewarm-runtime.yml', 'libvhdi-input-update.yml',
                 'update-rolling.yml', 'update-check.yml', 'security-scan.yml',
                 'consumer-probe.yml', 'queue-automation.yml', 'security-audit.yml',
                 'review-observer.yml', 'decision-authority.yml']
        for name in files:
            text = (ROOT / '.github/workflows' / name).read_text().split('\njobs:\n', 1)[1]
            for chunk in re.split(r'(?m)(?=^  [a-zA-Z0-9_-]+:\n)', text):
                if re.match(r'^  [a-zA-Z0-9_-]+:\n', chunk):
                    with self.subTest(name=name, job=chunk.splitlines()[0]):
                        self.assertIn("github.repository == 'closure-labs/xo-nixpkg'",
                                      chunk.split('    steps:', 1)[0])

    def test_public_candidate_workflows_remain_read_only_and_unrestricted(self):
        for name in ['ci.yml', 'repository-secret-scan.yml', 'codeql.yml', 'decision-events.yml']:
            text = (ROOT / '.github/workflows' / name).read_text()
            self.assertIn('pull_request:', text)
            self.assertNotIn("github.repository == 'closure-labs/xo-nixpkg'", text)
