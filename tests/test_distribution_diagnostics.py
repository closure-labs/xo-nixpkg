"""Bounded safe failure records; never invoke a real Nix command or store."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import traceback
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('distribution_diagnostics',
    Path(__file__).resolve().parents[1] / 'ci/distribution-cache.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class DiagnosticsTests(unittest.TestCase):
    def failure(self, stderr, args=None, code=1):
        args = args or ['nix', 'copy', '--to', 'file:///private/SENSITIVE?token=SECRET', '/nix/store/private']
        error = subprocess.CalledProcessError(code, args, output=b'PRIVATE_STDOUT', stderr=stderr)
        with patch.object(M.operations, 'run', side_effect=error):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                M.command(args)
        return raised.exception

    def test_nonzero_semantics_and_original_returncode_are_preserved(self):
        error = self.failure(b'error: no space left on device', code=7)
        self.assertIsInstance(error, subprocess.CalledProcessError)
        self.assertEqual(error.returncode, 7)
        self.assertEqual(error.diagnostic['operation'], 'export-copy')
        self.assertEqual(error.diagnostic['indicators'], ['disk-full'])
        self.assertFalse(error.diagnostic['authorityClaim'])

    def test_arbitrary_secrets_urls_paths_and_stdout_never_reach_diagnostics(self):
        error = self.failure(b'Authorization: Bearer SECRET\nhttps://private.invalid/key\n/private/path\nPRIVATE_PAYLOAD\npermission denied')
        encoded = str(error) + repr(error.cmd) + ''.join(traceback.format_exception(error))
        for forbidden in ('SECRET', 'private.invalid', '/private/path', 'PRIVATE_PAYLOAD', 'PRIVATE_STDOUT', 'SENSITIVE'):
            self.assertNotIn(forbidden, encoded)
        self.assertIsNone(error.output)
        self.assertIsNone(error.stderr)
        self.assertEqual(error.diagnostic['indicators'], ['permission-denied'])

    def test_tail_inspection_and_serialized_record_are_bounded(self):
        error = self.failure(b'no space left on device\n' + b'x' * (2 * M.STDERR_TAIL_BYTES))
        self.assertEqual(error.diagnostic['stderrTailBytes'], M.STDERR_TAIL_BYTES)
        self.assertTrue(error.diagnostic['stderrTailTruncated'])
        self.assertEqual(error.diagnostic['indicators'], ['unclassified'])
        self.assertLess(len(str(error).encode()), 4096)

    def test_no_indicator_does_not_invent_a_disk_failure(self):
        self.assertEqual(self.failure(b'unknown fixture failure').diagnostic['indicators'], ['unclassified'])
        self.assertEqual(self.failure(None).diagnostic['stderrTailBytes'], 0)

    def test_text_and_invalid_utf8_are_sanitized(self):
        for raw in ('PRIVATE_TEXT input/output error', b'\xffPRIVATE_BINARY disk quota exceeded'):
            error = self.failure(raw)
            self.assertNotIn('PRIVATE', str(error))
            self.assertNotEqual(error.diagnostic['indicators'], ['unclassified'])
        unicode_error = self.failure('\U0001f600' * M.STDERR_TAIL_BYTES)
        self.assertTrue(unicode_error.diagnostic['stderrTailTruncated'])
        self.assertEqual(unicode_error.diagnostic['stderrTailBytes'], M.STDERR_TAIL_BYTES)

    def test_only_allowlisted_operation_labels_are_emitted(self):
        error = self.failure(b'failure', args=['PRIVATE_PROGRAM', 'PRIVATE_ARG'])
        self.assertEqual(error.diagnostic['operation'], 'unknown')
        self.assertNotIn('PRIVATE', str(error) + repr(error.cmd))

    def test_numeric_before_after_resource_evidence_and_unavailable_probe(self):
        fake = SimpleNamespace(f_bavail=10, f_frsize=4096, f_favail=123)
        with patch.object(M.os, 'statvfs', return_value=fake):
            record = self.failure(b'failed').diagnostic['resources']
        for phase in ('before', 'after'):
            self.assertEqual(record[phase]['temporary']['availableBytes'], 40960)
            self.assertEqual(record[phase]['workspace']['availableInodes'], 123)
        with patch.object(M.os, 'statvfs', side_effect=OSError(13, 'PRIVATE probe detail')):
            error = self.failure(b'failed')
        self.assertNotIn('PRIVATE', str(error))
        self.assertEqual(error.diagnostic['resources']['after']['temporary'], {'status': 'unavailable', 'errno': 13})

    def test_success_and_timeout_behavior_are_unchanged(self):
        with patch.object(M.operations, 'run', return_value=SimpleNamespace(stdout=b'original bytes')) as run:
            self.assertEqual(M.command(['nix', 'path-info']), b'original bytes')
            self.assertEqual(run.call_args.kwargs, {'capture_output': True, 'check': True, 'timeout': 1800})
        with patch.object(M.operations, 'run', side_effect=subprocess.TimeoutExpired(['nix'], 1800)):
            with self.assertRaises(subprocess.TimeoutExpired):
                M.command(['nix'])

    def test_failure_is_not_retried_and_resource_snapshots_are_fresh(self):
        values = [SimpleNamespace(f_bavail=n, f_frsize=4096, f_favail=n) for n in (100, 100, 100, 10, 10, 10)]
        with patch.object(M.os, 'statvfs', side_effect=values) as probe:
            error = self.failure(b'failed')
        self.assertEqual(probe.call_count, 6)
        self.assertEqual(error.diagnostic['resources']['before']['temporary']['availableBytes'], 409600)
        self.assertEqual(error.diagnostic['resources']['after']['temporary']['availableBytes'], 40960)
        with patch.object(M.operations, 'run', side_effect=subprocess.CalledProcessError(1, ['nix'])) as run:
            with self.assertRaises(M.CommandFailure):
                M.command(['nix'])
        self.assertEqual(run.call_count, 1)

    def test_failed_export_creates_no_manifest_or_transport_parts(self):
        root = '/nix/store/' + 'a' * 32 + '-fixture'
        roots = [{'storePath': root, 'narHash': 'sha256-' + 'A' * 43 + '='}]
        def run(args, **kwargs):
            if args[:2] == ['nix', 'path-info']:
                return SimpleNamespace(stdout=json.dumps({root: {'narHash': roots[0]['narHash']}}).encode())
            raise subprocess.CalledProcessError(1, args, stderr=b'PRIVATE failure')
        with tempfile.TemporaryDirectory() as temporary, patch.object(M.operations, 'run', side_effect=run):
            output = Path(temporary) / 'payload'
            with self.assertRaises(M.CommandFailure):
                M.export(output, roots)
            self.assertEqual(list(output.iterdir()), [])

    def test_cli_failure_surfaces_only_safe_record_and_writes_no_success_manifest(self):
        root = '/nix/store/' + 'a' * 32 + '-fixture'
        nar = 'sha256-' + 'A' * 43 + '='
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / 'nix'
            binary.write_text('#!' + sys.executable + '\nimport json,sys\n'
                'if sys.argv[1] == "path-info":\n'
                ' print(json.dumps(' + repr({root: {'narHash': nar}}) + '))\n'
                'else:\n'
                ' print("PRIVATE_STDOUT")\n'
                ' sys.stderr.write("PRIVATE_CANARY https://private.invalid/token\\n" + "x" * 131072 + "\\nread-only file system")\n'
                ' sys.exit(3)\n')
            binary.chmod(0o755)
            roots, manifest = directory / 'roots.json', directory / 'manifest.json'
            roots.write_text(json.dumps([{'storePath': root, 'narHash': nar}]))
            result = subprocess.run([sys.executable, str(Path(M.__file__)), '--export',
                '--directory', str(directory / 'output'), '--roots', str(roots),
                '--manifest', str(manifest)], env=dict(os.environ, PATH=str(directory) + os.pathsep + os.environ['PATH']),
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(manifest.exists())
            record = json.loads(result.stderr.rsplit('Distribution command failed: ', 1)[1])
            self.assertEqual(record['returncode'], 3)
            self.assertEqual(record['operation'], 'export-copy')
            self.assertEqual(record['indicators'], ['read-only-filesystem'])
            self.assertTrue(record['stderrTailTruncated'])
            for private in ('PRIVATE_STDOUT', 'PRIVATE_CANARY', 'private.invalid'):
                self.assertNotIn(private, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
