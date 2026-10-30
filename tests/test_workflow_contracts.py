# SPDX-License-Identifier: Apache-2.0
"""Workflow entrypoints retain task, token, branch and paired-lock contracts."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github/workflows'


class WorkflowContracts(unittest.TestCase):
    def test_every_setup_nix_call_passes_the_required_token(self):
        for path in WORKFLOWS.glob('*.yml'):
            source = path.read_text()
            for block in re.split(r'(?m)^      - ', source):
                if 'uses: ./.github/actions/setup-nix' in block:
                    with self.subTest(workflow=path.name):
                        self.assertIn('github-token: ${{ github.token }}', block)

    def test_privileged_producers_only_run_for_main(self):
        for name, job in [('qualification.yml', 'qualify'), ('update-check.yml', 'update'),
                          ('update-rolling.yml', 'update'),
                          ('libvhdi-input-update.yml', 'update')]:
            with self.subTest(workflow=name):
                source = (WORKFLOWS / name).read_text()
                self.assertRegex(source, rf"  {job}:\n    if: github.ref == 'refs/heads/main'")

    def test_native_dependabot_owns_nixpkgs_schedule(self):
        self.assertFalse((WORKFLOWS / 'update-flake-lock.yml').exists())
        self.assertIn('package-ecosystem: nix', (ROOT / '.github/dependabot.yml').read_text())
        self.assertIn('dependency-name: nixpkgs', (ROOT / '.github/dependabot.yml').read_text())
        self.assertIn('"0 6,18 * * *"', (WORKFLOWS / 'update-check.yml').read_text())

    def test_reconciliation_binds_qualification_completion_to_its_run_and_attempt(self):
        source = (WORKFLOWS / 'security-reconcile.yml').read_text()
        for variable, field in [('QUALIFICATION_RUN', 'id'), ('QUALIFICATION_ATTEMPT', 'run_attempt')]:
            line = next(line for line in source.splitlines() if line.strip().startswith(variable + ':'))
            self.assertIn("github.event_name == 'workflow_run'", line)
            self.assertIn("github.event.workflow_run.name == 'Qualify immutable products'", line)
            self.assertIn('github.event.workflow_run.' + field, line)

    def test_referenced_workflow_tasks_are_declared(self):
        tasks = set(re.findall(r'"([a-z-]+:[a-z-]+)"\.exec', (ROOT / 'devenv.nix').read_text()))
        for path in WORKFLOWS.glob('*.yml'):
            for line in path.read_text().splitlines():
                if 'tasks run' in line:
                    for task in re.findall(r'\b[a-z-]+:[a-z-]+\b', line):
                        if task != 'packages:pkgs':
                            self.assertIn(task, tasks, f'{path.name}: {task}')
