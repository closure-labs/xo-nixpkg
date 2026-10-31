# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
from pathlib import Path
import unittest
import tempfile

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

    def test_cgroup_requires_enforced_physical_cpu_swap_and_task_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); unit = root/'unit'; unit.mkdir()
            controls = {'memory.max': '3221225472', 'memory.swap.max': '0', 'cpu.max': '100000 100000', 'pids.max': '128'}
            for name, value in controls.items():
                (unit/name).write_text(value)
            caps = m.verify_cgroup(root, '0::/unit')
            self.assertEqual(caps['physicalMemoryMaxBytes'], 3*1024**3)
            for name, bad in [('memory.max', 'max'), ('memory.max', '3221225473'), ('memory.swap.max', '1'), ('cpu.max', 'max 100000'), ('cpu.max', '200000 100000'), ('pids.max', 'max')]:
                (unit/name).write_text(bad)
                with self.assertRaises(m.Blocked):
                    m.verify_cgroup(root, '0::/unit')
                (unit/name).write_text(controls[name])
            with self.assertRaises(m.Blocked):
                m.verify_cgroup(root, '0::/../escape')

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
