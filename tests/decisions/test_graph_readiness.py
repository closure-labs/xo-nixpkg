"""Graph planning cannot grant admission or bypass malformed decision history."""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci/decisions'))
import readiness
from test_core import CFG
import test_core


class GraphReadiness(unittest.TestCase):
    def invoke(self, records, graph_only=True):
        arguments = ['readiness', '--config', 'fixture.json'] + (['--graph-only'] if graph_only else [])
        output = io.StringIO()
        with patch.object(sys, 'argv', arguments), \
                patch.object(readiness, 'config', return_value=CFG) as config, \
                patch.object(readiness, 'ledger', return_value=('a' * 40, records)), \
                patch.object(readiness, 'required_check') as check, \
                patch.object(readiness, 'active_security', wraps=readiness.active_security) as select, \
                contextlib.redirect_stdout(output):
            readiness.main()
        config.assert_called_once_with(Path('fixture.json'), live=True, enabled=True)
        return json.loads(output.getvalue()), check, select

    def test_empty_graph_is_valid_scheduling_metadata_without_acceptance(self):
        result, check, select = self.invoke({})
        self.assertIsNone(result['decisionHash'])
        self.assertIs(result['authorityClaim'], False)
        check.assert_not_called()
        self.assertFalse(select.call_args.kwargs['authenticate'])

    def test_normal_readiness_still_requires_an_accepted_baseline(self):
        with self.assertRaisesRegex(ValueError, 'Accepted initial baseline'):
            self.invoke({}, graph_only=False)

    def test_ambiguous_or_malformed_graph_remains_blocked(self):
        one, two = test_core.Core().proposal(), test_core.Core().proposal('rejected')
        records = {str(index): proposal for index, proposal in enumerate((one, two))}
        with self.assertRaisesRegex(ValueError, 'Ambiguous concurrent'):
            self.invoke(records)
        one['payload']['supersedes'] = ['missing']
        with self.assertRaisesRegex(ValueError, 'Invalid supersession parents'):
            self.invoke({'one': one})


if __name__ == '__main__':
    unittest.main()
