# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('diagnostic_secret_triage', Path(__file__).resolve().parents[1]/'ci/diagnostic-secret-triage.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class SanitizerTests(unittest.TestCase):
    def test_only_location_metadata_survives(self):
        sha = 'a'*40
        finding = {'RuleID': 'generic-api-key', 'File': 'ci/compare-retained-nars.py', 'StartLine': 41, 'Commit': sha,
                   'Secret': 'redacted', 'Match': 'redacted', 'Fragment': 'redacted'}
        rows = m.sanitize([finding], {sha})
        self.assertEqual(set(rows[0]), {'rule', 'file', 'line', 'commit'})
        self.assertNotIn('redacted', json.dumps(rows))

    def test_malformed_unknown_and_foreign_entries_fail(self):
        good = {'RuleID': 'generic-api-key', 'File': 'ci/compare-retained-nars.py', 'StartLine': 41, 'Commit': 'a'*40}
        for key, bad in [('RuleID', 'PRIVATE\nPAYLOAD'), ('File', 'redacted'), ('StartLine', True), ('StartLine', -1), ('Commit', 'b'*40)]:
            with self.assertRaises(m.Blocked):
                m.sanitize([dict(good, **{key: bad})], {'a'*40})
        for bad in [None, {}, [None], [good]*1001]:
            with self.assertRaises(m.Blocked):
                m.sanitize(bad, {'a'*40})


if __name__ == '__main__':
    unittest.main()
