# SPDX-License-Identifier: Apache-2.0
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_normalize', ROOT / 'ci/security-normalize.py')
normalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalizer)
spec = importlib.util.spec_from_file_location('admission', ROOT / 'ci/decisions/security_decisions.py')
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


class RelatedAdvisoryTests(unittest.TestCase):
    def normalize(self, primary, related):
        component = {'purl': 'pkg:nix/fixture@1', 'properties': [
            {'name': 'nix:storePath', 'value': '/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture'},
            {'name': 'xo-nixpkg:outputName', 'value': 'lib'},
            {'name': 'xo-nixpkg:installedPath', 'value': '/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture/lib/code.so'}]}
        return normalizer.normalize({'components': [component]}, {'matches': [{
            'artifact': {'purl': component['purl']}, 'vulnerability': primary,
            'relatedVulnerabilities': related}]})['observations'][0]

    def test_related_risk_is_retained_for_admission(self):
        result = self.normalize({'id': 'GHSA-fixture', 'severity': 'Low',
                                 'cvss': [{'metrics': {'baseScore': 2.1}}]}, [
            {'id': 'CVE-2026-12345', 'severity': 'Critical', 'knownExploited': [{}],
             'cvss': [{'metrics': {'baseScore': 9.8}}]}])
        self.assertEqual(result['severity'], 'Low')
        self.assertEqual(result['admissionSeverity'], 'Critical')
        self.assertEqual(sorted(v['metrics']['baseScore'] for v in result['cvss']), [2.1, 9.8])
        self.assertTrue(result['knownExploited'])
        self.assertEqual(result['aliases'], ['CVE-2026-12345', 'GHSA-fixture'])

    def test_related_lower_risk_cannot_downgrade_primary(self):
        result = self.normalize({'id': 'GHSA-fixture', 'severity': 'Critical',
                                 'knownExploited': True}, [
            {'id': 'CVE-2026-12345', 'severity': 'Low', 'knownExploited': False}])
        self.assertEqual(result['admissionSeverity'], 'Critical')
        self.assertTrue(result['knownExploited'])

    def test_related_risk_requires_new_human_admission(self):
        primary = {'id': 'GHSA-fixture', 'severity': 'Low',
                   'cvss': [{'metrics': {'baseScore': 2.1}}]}
        before = self.normalize(primary, [{'id': 'CVE-2026-12345'}])
        after = self.normalize(primary, [{'id': 'CVE-2026-12345', 'severity': 'Critical',
            'cvss': [{'metrics': {'baseScore': 9.8}}], 'knownExploited': [{}]}])
        scan = lambda observation: {'status': 'complete', 'scannerHealth': 'healthy',
                                    'observations': [observation]}
        accepted = admission.normalize_findings(scan(before), 'xo-latest')
        result = admission.evaluate(scan(after), 'xo-latest', accepted)
        self.assertEqual(result['status'], 'review-required')
        self.assertEqual(result['findings'][0]['severity'], 'Critical')
        self.assertEqual(result['findings'][0]['cvss'], 9.8)

    def test_explicit_related_aliases_are_retained(self):
        result = self.normalize({'id': 'GHSA-fixture'}, [
            {'id': 'CVE-2026-12345', 'aliases': ['GO-2026-1234']}])
        self.assertIn('GO-2026-1234', result['aliases'])

    def test_missing_related_metadata_preserves_unknown(self):
        result = self.normalize({'id': 'GHSA-fixture'}, [{'id': 'CVE-2026-12345'}])
        self.assertEqual(result['admissionSeverity'], 'Unknown')
        self.assertEqual(result['cvss'], [])
        self.assertFalse(result['knownExploited'])

    def test_malformed_related_metadata_is_a_technical_failure(self):
        malformed = [None, {}, 'CVE-2026-12345', [None], [{}],
                     [{'id': 'CVE-2026-12345', 'severity': 'urgent'}],
                     [{'id': 'CVE-2026-12345', 'aliases': 'GO-2026-1234'}],
                     [{'id': 'CVE-2026-12345', 'cvss': 9.8}],
                     [{'id': 'CVE-2026-12345', 'cvss': [None]}],
                     [{'id': 'CVE-2026-12345', 'cvss': [{'metrics': {'baseScore': True}}]}],
                     [{'id': 'CVE-2026-12345', 'cvss': [{'metrics': {'baseScore': float('nan')}}]}],
                     [{'id': 'CVE-2026-12345', 'cvss': [{'metrics': {'baseScore': 10.1}}]}],
                     [{'id': 'CVE-2026-12345', 'knownExploited': 'false'}],
                     [{'id': 'CVE-2026-12345', 'knownExploited': 0}]]
        for related in malformed:
            with self.subTest(related=related), self.assertRaises(ValueError):
                self.normalize({'id': 'GHSA-fixture', 'severity': 'Low'}, related)


if __name__ == '__main__':
    unittest.main()
