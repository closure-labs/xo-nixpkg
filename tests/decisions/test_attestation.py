#!/usr/bin/env python3
"""Exercise bounded verifier failures with real, credential-free subprocesses."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci/decisions'))
import common

SECRET = 'PRIVATE-VERIFIER-TEXT-DO-NOT-LOG'


class Attestation(unittest.TestCase):
    def child(self, body):
        return common.attestation_command([sys.executable, '-c', body])

    def failure(self, stderr, code=1):
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            self.child('import sys; sys.stderr.write(' + repr(stderr) + '); sys.exit(' + str(code) + ')')
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertNotIn(SECRET, repr(caught.exception))
        self.assertIsNone(caught.exception.stderr)
        self.assertIsNone(caught.exception.stdout)
        return caught.exception, json.loads(str(caught.exception).split(': ', 1)[1])

    def test_success_returns_verified_json_and_preserves_all_verifier_flags(self):
        proof = [{'verificationResult': {'statement': {'predicate': {}}}}]
        self.assertEqual(self.child('print(' + repr(json.dumps(proof)) + ')'), proof)
        with patch.object(common, 'attestation_command', return_value=proof) as run:
            self.assertEqual(common.attest(Path('/private/evidence.json'),
                                          {'repository': 'closure-labs/xo-nixpkg'},
                                          'a' * 40, '.github/workflows/qualification.yml'), proof)
        self.assertEqual(run.call_args.args[0], [
            'gh', 'attestation', 'verify', '/private/evidence.json', '--repo', 'closure-labs/xo-nixpkg',
            '--signer-workflow', 'closure-labs/xo-nixpkg/.github/workflows/qualification.yml',
            '--source-digest', 'a' * 40, '--source-ref', 'refs/heads/main',
            '--deny-self-hosted-runners', '--format', 'json'])
        run.assert_called_once()

    def test_invalid_signature_fails_closed_without_retaining_remote_text(self):
        error, diagnostic = self.failure('Invalid signature: ' + SECRET + ' https://private.invalid/token')
        self.assertEqual(error.returncode, 1)
        self.assertEqual(diagnostic['categories'], ['signature-invalid'])
        self.assertEqual(diagnostic['httpStatus'], [])
        self.assertNotIn('private.invalid', str(error))

    def test_authentication_and_transient_http_errors_are_classified_without_retries(self):
        for status, category in [(401, 'authorization-denied'), (403, 'authorization-denied'),
                                 (429, 'rate-limited'), (500, 'remote-server'),
                                 (502, 'remote-server'), (503, 'remote-server'), (504, 'remote-server')]:
            with self.subTest(status=status):
                _, diagnostic = self.failure('HTTP ' + str(status) + ': ' + SECRET)
                self.assertEqual(diagnostic['categories'], [category])
                self.assertEqual(diagnostic['httpStatus'], [status])

    def test_identity_network_tls_and_local_storage_failures_remain_distinct(self):
        for text, category in [('source digest does not match', 'identity-mismatch'),
                               ('connection reset by peer', 'network'),
                               ('x509: certificate signed by unknown authority', 'tls'),
                               ('no space left on device', 'disk-full'),
                               ('no attestations found', 'attestation-unavailable'),
                               ('failed to update TUF metadata', 'trust-root')]:
            with self.subTest(category=category):
                _, diagnostic = self.failure(text + ' ' + SECRET)
                self.assertEqual(diagnostic['categories'], [category])

    def test_unrecognized_remote_failures_are_not_guessed_or_printed(self):
        error, diagnostic = self.failure(SECRET + ' /private/secret.pem https://private.invalid/path')
        self.assertEqual(diagnostic['categories'], ['unclassified'])
        for private in ['/private/', 'private.invalid', 'secret.pem']:
            self.assertNotIn(private, str(error))

    def test_large_stderr_is_drained_with_only_a_bounded_tail(self):
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            self.child('import sys; sys.stderr.write(' + repr(SECRET) + " * 50000 + '\\nHTTP 503'); sys.exit(1)")
        error = caught.exception
        diagnostic = json.loads(str(error).split(': ', 1)[1])
        self.assertTrue(diagnostic['stderrTruncated'])
        self.assertEqual(diagnostic['stderrBytes'], len(SECRET.encode()) * 50000 + len('\nHTTP 503'))
        self.assertEqual(diagnostic['categories'], ['remote-server'])
        self.assertNotIn(SECRET, str(error))
        self.assertLess(len(str(error)), 1024)

    def test_stdout_limit_fails_closed_before_returning_any_proof(self):
        with patch.object(common, 'ATTESTATION_STDOUT_LIMIT', 1024), self.assertRaises(ValueError) as caught:
            self.child('import sys; sys.stdout.write(' + repr(SECRET) + ' * 10000)')
        diagnostic = json.loads(str(caught.exception).split(': ', 1)[1])
        self.assertEqual(diagnostic['categories'], ['output-limit'])
        self.assertNotIn(SECRET, str(caught.exception))

    def test_timeout_kills_child_and_has_no_raw_command_or_stderr(self):
        with patch.object(common, 'ATTESTATION_TIMEOUT', .05), \
             self.assertRaises(subprocess.TimeoutExpired) as caught:
            self.child('import sys,time; sys.stderr.write(' + repr(SECRET) + '); sys.stderr.flush(); time.sleep(10)')
        diagnostic = json.loads(str(caught.exception).split(': ', 1)[1])
        self.assertEqual(diagnostic['categories'], ['timeout'])
        self.assertTrue(diagnostic['timedOut'])
        self.assertEqual(diagnostic['timeoutSeconds'], .05)
        self.assertIsNone(caught.exception.stderr)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_launch_failure_reports_only_numeric_errno(self):
        with patch.object(common.subprocess, 'Popen', side_effect=FileNotFoundError(2, SECRET)), \
             self.assertRaises(ValueError) as caught:
            self.child(SECRET)
        diagnostic = json.loads(str(caught.exception).split(': ', 1)[1])
        self.assertEqual(diagnostic['categories'], ['start-failed'])
        self.assertEqual(diagnostic['errno'], 2)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_malformed_success_output_is_rejected_without_echoing_bytes(self):
        for body in ['print(' + repr(SECRET) + ')', "import sys; sys.stdout.buffer.write(bytes([255]))"]:
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, '^Invalid attestation verifier JSON output$'):
                self.child(body)

    def test_nonzero_exit_preserves_existing_product_signer_fallback(self):
        error, _ = self.failure('Invalid signature ' + SECRET)
        proof = [{'verified': True}]
        cfg = {'producerWorkflows': ['first.yml', 'second.yml']}
        with patch.object(common, 'attest', side_effect=[error, proof]) as attest:
            self.assertEqual(common.attest_product(Path('product.json'), cfg, 'a' * 40), proof)
            self.assertEqual(attest.call_count, 2)
        with patch.object(common, 'attest', side_effect=error) as attest, \
             self.assertRaisesRegex(ValueError, 'Product has no trusted original producer attestation'):
            common.attest_product(Path('product.json'), cfg, 'a' * 40)
        self.assertEqual(attest.call_count, 2)

    def test_timeout_is_not_reinterpreted_as_an_alternative_signer(self):
        failure = common.AttestationTimeout('safe timeout', 180)
        with patch.object(common, 'attest', side_effect=failure) as attest, \
             self.assertRaises(subprocess.TimeoutExpired):
            common.attest_product(Path('product.json'), {'producerWorkflows': ['first.yml', 'second.yml']}, 'a' * 40)
        attest.assert_called_once()

    def test_cli_emits_only_safe_structured_failure(self):
        error, _ = self.failure('HTTP 403 ' + SECRET)
        stream = io.StringIO()
        with patch.object(common, 'attest', side_effect=error), contextlib.redirect_stderr(stream):
            self.assertEqual(common.run(lambda: common.attest(Path(SECRET), {}, SECRET, SECRET)), 2)
        value = json.loads(stream.getvalue())
        self.assertEqual(value['status'], 'blocked')
        self.assertNotIn(SECRET, value['error'])


if __name__ == '__main__':
    unittest.main()
