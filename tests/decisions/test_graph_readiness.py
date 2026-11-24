"""Graph planning cannot grant admission or bypass malformed decision history."""
import contextlib
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci/decisions'))
import readiness
from test_core import CFG
import test_core


class GraphReadiness(unittest.TestCase):
    def invoke(self, records, graph_only=True, output_path=None):
        arguments = ['readiness', '--config', 'fixture.json'] + (['--graph-only'] if graph_only else [])
        if output_path is not None:
            arguments += ['--output', str(output_path)]
        output = io.StringIO()
        with patch.object(sys, 'argv', arguments), \
                patch.object(readiness, 'config', return_value=CFG) as config, \
                patch.object(readiness, 'ledger', return_value=('a' * 40, records)), \
                patch.object(readiness, 'required_check') as check, \
                patch.object(readiness, 'active_security', wraps=readiness.active_security) as select, \
                patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': ''}), \
                contextlib.redirect_stdout(output):
            code = readiness.main()
        config.assert_called_once_with(Path('fixture.json'), live=True, enabled=True)
        return json.loads(output.getvalue()), check, select, code

    def test_empty_graph_is_valid_scheduling_metadata_without_acceptance(self):
        result, check, select, code = self.invoke({})
        self.assertIsNone(result['decisionHash'])
        self.assertIs(result['authorityClaim'], False)
        check.assert_not_called()
        self.assertIs(result['publicationReady'], False)
        self.assertEqual(result['leafCount'], 0)
        self.assertEqual(code, 0)
        select.assert_not_called()

    def test_normal_readiness_still_requires_an_accepted_baseline(self):
        with self.assertRaisesRegex(ValueError, 'Accepted initial baseline'):
            self.invoke({}, graph_only=False)

    def test_ambiguous_graph_is_retained_and_never_selects_a_winner(self):
        one, two = test_core.Core().proposal(), test_core.Core().proposal('rejected')
        records = {readiness.canonical_hash(value): value for value in (one, two)}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'report.json'
            result, check, select, code = self.invoke(records, output_path=path)
            self.assertEqual(json.loads(path.read_text()), result)
        self.assertEqual(code, 2)
        self.assertEqual(result['status'], 'ambiguous-security-graph')
        self.assertEqual(result['mainRevision'], 'a' * 40)
        self.assertEqual(result['graphHash'], readiness.canonical_hash(records))
        self.assertEqual(result['policyHash'], readiness.canonical_hash(CFG))
        self.assertEqual([entry['decisionHash'] for entry in result['leaves']], sorted(records))
        self.assertEqual(result['leafCount'], 2)
        self.assertIsNone(result['decisionHash'])
        self.assertTrue(result['requiresHumanReview'])
        self.assertFalse(result['authorityClaim'])
        self.assertFalse(result['publicationReady'])
        check.assert_not_called()
        select.assert_not_called()

    def test_equivalent_accepted_scopes_still_require_explicit_reconciliation(self):
        one = test_core.Core().proposal()
        two = deepcopy(one)
        two['payload']['rationale'] = 'Separately reviewed equivalent evidence'
        records = {readiness.canonical_hash(value): value for value in (one, two)}
        result, _, _, code = self.invoke(records)
        self.assertTrue(result['scopesIdentical'])
        self.assertTrue(result['requiresHumanReview'])

    def test_report_write_errors_preserve_success_and_ambiguous_failure(self):
        one, two = test_core.Core().proposal(), test_core.Core().proposal('rejected')
        for records, expected in (({}, 0), ({'b' * 64: one, 'c' * 64: two}, 2)):
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                result, _, _, code = self.invoke(records,
                    output_path=Path('/dev/null/private-sentinel'))
            self.assertEqual(code, expected)
            self.assertEqual(result['requiresHumanReview'], expected == 2)
            self.assertIn('graph verdict is unchanged', error.getvalue())
            self.assertNotIn('private-sentinel', error.getvalue())
        self.assertEqual(code, 2)

    def test_single_leaf_metadata_cannot_authorize_publication(self):
        one = test_core.Core().proposal()
        digest = readiness.canonical_hash(one)
        result, _, select, code = self.invoke({digest: one})
        self.assertEqual(code, 0)
        self.assertEqual(result['decisionHash'], digest)
        self.assertFalse(result['authorityClaim'])
        self.assertFalse(result['publicationReady'])
        select.assert_not_called()

    def test_malformed_graph_and_cycles_remain_errors_without_a_report(self):
        one = test_core.Core().proposal()
        one['payload']['supersedes'] = ['missing']
        with self.assertRaisesRegex(ValueError, 'Invalid supersession parents'):
            self.invoke({'one': one})
        two = deepcopy(one)
        one['payload']['supersedes'] = ['two']
        two['payload']['supersedes'] = ['one']
        with self.assertRaisesRegex(ValueError, 'Cyclic decision supersession'):
            self.invoke({'one': one, 'two': two})

    def test_blocked_summary_uses_only_validated_graph_metadata(self):
        one, two = test_core.Core().proposal(), test_core.Core().proposal('rejected')
        one['payload']['rationale'] = 'private-sentinel-not-a-diagnostic'
        report = readiness.graph_report(CFG, 'a' * 40, {'b' * 64: one, 'c' * 64: two})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'summary.md'
            with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(path)}):
                readiness.summary(report)
            text = path.read_text()
        self.assertIn('Release blocked', text)
        self.assertIn('b' * 64, text)
        self.assertNotIn('private-sentinel', text)


if __name__ == '__main__':
    unittest.main()
