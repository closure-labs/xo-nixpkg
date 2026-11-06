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
                self.assertRegex(source, rf"  {job}:\n    if: github.repository == 'closure-labs/xo-nixpkg' && \(github.ref == 'refs/heads/main'\)")

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
            self.assertIn("github.event.workflow_run.name == 'Qualify release products'", line)
            self.assertIn('github.event.workflow_run.' + field, line)

    def test_referenced_workflow_tasks_are_declared(self):
        tasks = set(re.findall(r'"([a-z-]+:[a-z-]+)"\.exec', (ROOT / 'devenv.nix').read_text()))
        for path in WORKFLOWS.glob('*.yml'):
            for line in path.read_text().splitlines():
                if 'tasks run' in line:
                    for task in re.findall(r'\b[a-z-]+:[a-z-]+\b', line):
                        if task != 'packages:pkgs':
                            self.assertIn(task, tasks, f'{path.name}: {task}')

    def test_rolling_publication_uses_only_a_late_scoped_app_token(self):
        # BaseLoader preserves GitHub's `on` and expression scalars unchanged.
        import yaml
        source = (WORKFLOWS / 'update-rolling.yml').read_text()
        workflow = yaml.load(source, Loader=yaml.BaseLoader)
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        steps = workflow['jobs']['update']['steps']
        by_id = {step['id']: step for step in steps if 'id' in step}
        publisher, rolling, prewarm, writer = (by_id[key] for key in
                                              ('publisher', 'rolling', 'prewarm', 'writer'))
        for before, after in ((publisher, rolling), (rolling, prewarm), (prewarm, writer)):
            self.assertLess(steps.index(before), steps.index(after))
        checkout = next(step for step in steps if step.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['ref'], '${{ github.sha }}')
        self.assertEqual(checkout['with']['persist-credentials'], 'false')
        self.assertIn('nix build .#open-update-pr --no-link --print-out-paths', publisher['run'])
        packages = (ROOT / 'flake.nix').read_text().split('      packages = ', 1)[1].split('      devShells = ', 1)[0]
        self.assertIn('open-update-pr = applications.openUpdatePr;', packages)
        self.assertIn('^/nix/store/[a-z0-9]{32}-xo-nixpkg-open-update-pr$', publisher['run'])
        self.assertEqual(writer['uses'],
                         'actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510')
        self.assertEqual(writer['with'], {
            'client-id': '${{ vars.DECIDER_CLIENT }}',
            'private-key': '${{ secrets.DECIDER_KEY }}',
            'owner': '${{ github.repository_owner }}', 'repositories': 'xo-nixpkg',
            'permission-contents': 'write', 'permission-pull-requests': 'write',
        })
        self.assertIn("steps.rolling.outputs.changed == 'true'", writer['if'])
        self.assertIn('!cancelled()', writer['if'])
        # No skip-token-revoke override, credentials in preparation, or mutable
        # Nix evaluation/builds after minting, including the broken-candidate path.
        for step in steps[:steps.index(writer)]:
            self.assertNotIn('DECIDER_', str(step))
            self.assertNotIn('steps.writer.outputs.token', str(step))
        after_mint = steps[steps.index(writer) + 1:]
        publication = after_mint[0]
        self.assertEqual(publication['env']['GH_TOKEN'], '${{ steps.writer.outputs.token }}')
        self.assertEqual(publication['env']['PUBLISHER_TOOL'], '${{ steps.publisher.outputs.path }}')
        self.assertEqual(publication['run'],
                         '"$PUBLISHER_TOOL/bin/xo-nixpkg-open-update-pr" flake.nix flake.lock nix/sources/xen-orchestra.json')
        self.assertIn("steps.writer.outcome == 'success'", publication['if'])
        self.assertIn('!cancelled()', publication['if'])
        self.assertEqual(publication['env']['UPDATE_DRAFT'], "${{ steps.prewarm.outcome != 'success' }}")
        self.assertEqual(prewarm['continue-on-error'], 'true')
        self.assertIn("steps.prewarm.outcome != 'success'", after_mint[-1]['if'])
        self.assertIn('exit 1', after_mint[-1]['run'])
        for step in after_mint:
            self.assertNotRegex(step.get('run', ''), r'\bnix\s+(?:run|build|eval)\b|\bdevenv\s|\./ci/|\./scripts/')
        self.assertEqual(source.count('steps.writer.outputs.token'), 1)
