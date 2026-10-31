"""Publication metadata limits and safe diagnostics, without large allocations."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('publication_limit_gate', ROOT / 'ci/audit-freshness.py')
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)


class PublicationEvidenceLimits(unittest.TestCase):
    def file(self, size, *, regular=True, symlink=False):
        directory, path = Mock(), Mock()
        directory.__truediv__ = Mock(return_value=path)
        path.is_file.return_value = regular
        path.is_symlink.return_value = symlink
        path.stat.return_value.st_size = size
        path.read_bytes.return_value = b'{}'
        return directory, path

    def test_exact_caps_accept_and_one_byte_over_rejects_before_read(self):
        for name, limit in [('product.json', 16 * 1024**2), ('scans.json', 128 * 1024**2)]:
            for size in [limit - 1, limit]:
                with self.subTest(name=name, size=size):
                    directory, path = self.file(size)
                    self.assertEqual(GATE.read_evidence(directory, name), {})
                    path.read_bytes.assert_called_once_with()
            directory, path = self.file(limit + 1)
            with self.assertRaisesRegex(GATE.native.Blocked, '^evidence-file$'):
                GATE.read_evidence(directory, name)
            path.read_bytes.assert_not_called()

    def test_measured_qualification_size_fits_scan_only(self):
        # Authenticated ZIP directory metadata from qualification 41145005348;
        # this fixture does not allocate or claim to validate the actual report.
        for name, accepted in [('scans.json', True), ('product.json', False)]:
            directory, path = self.file(90856690)
            if accepted:
                self.assertEqual(GATE.read_evidence(directory, name), {})
            else:
                with self.assertRaises(GATE.native.Blocked):
                    GATE.read_evidence(directory, name)
                path.read_bytes.assert_not_called()

    def test_only_exact_members_receive_limits(self):
        for name in ['nested/scans.json', 'other.json', '../scans.json']:
            directory, path = self.file(1)
            with self.assertRaises(GATE.native.Blocked):
                GATE.read_evidence(directory, name)
            path.read_bytes.assert_not_called()

    def test_links_and_nonregular_files_still_fail_before_read(self):
        for name in ['product.json', 'scans.json']:
            for regular, symlink in [(False, False), (True, True)]:
                directory, path = self.file(1, regular=regular, symlink=symlink)
                with self.assertRaises(GATE.native.Blocked):
                    GATE.read_evidence(directory, name)
                path.read_bytes.assert_not_called()

    def test_small_documents_still_use_strict_json_decoder(self):
        for raw in [b'{', b'{"key":1,"key":2}', b'{"key":NaN}']:
            directory, path = self.file(len(raw))
            path.read_bytes.return_value = raw
            with self.assertRaises(GATE.native.Blocked):
                GATE.read_evidence(directory, 'scans.json')

    def test_diagnostics_allow_only_fixed_guard_codes(self):
        self.assertEqual(GATE.failure_message(GATE.native.Blocked('evidence-file')),
                         'Publication blocked: security prerequisite failed (evidence-file)')
        for error in [ValueError('PRIVATE_TOKEN /private/path'),
                      GATE.native.Blocked('PRIVATE_TOKEN /private/path'),
                      ValueError('evidence-file')]:
            self.assertEqual(GATE.failure_message(error),
                             'Publication blocked: security prerequisite failed (validation-failed)')


if __name__ == '__main__':
    unittest.main()
