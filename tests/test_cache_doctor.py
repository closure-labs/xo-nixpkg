# SPDX-License-Identifier: Apache-2.0
"""Credential diagnostics must never disclose provider/API bodies or follow redirects."""
import importlib.util
import io
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import time
import unittest
import urllib.error
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'ci/cache-doctor.py'
sys.path.insert(0, str(ROOT / 'ci/decisions'))
spec = importlib.util.spec_from_file_location('cache_doctor', SOURCE)
doctor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doctor)
KEY = 'xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E='
TOKEN = 'fixture-secret-never-output'


class Response(io.BytesIO):
    status = 200


class Opener:
    def __init__(self, **changes):
        self.value = dict(name='xen-orchestra-ce', uri='https://xen-orchestra-ce.cachix.org',
                          publicSigningKeys=[KEY], permission='Write', **changes)

    def open(self, request, timeout):
        assert request.full_url == 'https://cachix.org/api/v1/cache/xen-orchestra-ce'
        assert request.get_header('Authorization') == 'Bearer ' + TOKEN
        assert timeout == 30
        return Response(json.dumps(self.value).encode())


class DoctorTests(unittest.TestCase):
    def test_native_development_profile_excludes_runtime_credentials(self):
        executable = os.environ.get('SECRETSPEC_BIN')
        if not executable:
            self.skipTest('Native contract supplies the pinned SecretSpec executable')
        with tempfile.TemporaryDirectory() as directory:
            manifest = tomllib.loads((ROOT / 'secretspec.toml').read_text())
            environment = dict(os.environ, XDG_CONFIG_HOME=directory, XDG_STATE_HOME=directory)
            environment.update({name: TOKEN for name in manifest['profiles']['runtime']})
            for profile in ('default', 'development'):
                result = subprocess.run([executable, 'export', '--file', str(ROOT / 'secretspec.toml'),
                                         '--provider', 'env', '--profile', profile, '--format', 'json',
                                         '--reason', 'Test isolated development credential boundaries'],
                                        env=environment, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, 'Public development profile failed')
                self.assertNotIn(TOKEN, result.stdout)
                self.assertNotIn(TOKEN, result.stderr)
                self.assertLessEqual(set(json.loads(result.stdout)), set(manifest['profiles']['default']))

    def test_identity_permissions_and_read_only_result(self):
        opener = Opener()
        result = doctor.inspect_cache('xen-orchestra-ce', KEY, TOKEN, opener)
        self.assertTrue(result['canWrite'])
        opener.value['permission'] = 'Read'
        self.assertFalse(doctor.inspect_cache('xen-orchestra-ce', KEY, TOKEN, opener)['canWrite'])
        opener.value['permission'] = 'Admin'
        self.assertTrue(doctor.inspect_cache('xen-orchestra-ce', KEY, TOKEN, opener)['canWrite'])
        for field, value in [('name', 'wrong'), ('uri', 'https://wrong.cachix.org'),
                             ('publicSigningKeys', ['wrong']), ('permission', 'unknown')]:
            wrong = Opener(); wrong.value[field] = value
            with self.subTest(field=field), self.assertRaises(doctor.DiagnosticError):
                doctor.inspect_cache('xen-orchestra-ce', KEY, TOKEN, wrong)

    def test_redirect_is_rejected(self):
        with self.assertRaises(doctor.DiagnosticError):
            doctor.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.test')

    def run_main(self, opener):
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), patch.object(doctor, 'resolve_token', return_value=TOKEN), \
             patch.object(doctor.urllib.request, 'build_opener', return_value=opener), \
             patch('sys.argv', ['cache-doctor']), patch('sys.stdout', output):
            status = doctor.main()
        self.assertNotIn(TOKEN, output.getvalue())
        return status, json.loads(output.getvalue())

    def test_failure_bodies_are_withheld_and_public_read_is_not_success(self):
        for code, expected in [(401, 'token-rejected'), (403, 'token-rejected'),
                               (503, 'cache-unavailable')]:
            opener = Opener()
            opener.open = lambda *a, code=code, **k: (_ for _ in ()).throw(
                urllib.error.HTTPError('https://cachix.org', code, TOKEN, {}, io.BytesIO(TOKEN.encode())))
            status, value = self.run_main(opener)
            self.assertEqual(status, 1)
            self.assertEqual(value['error'], expected)
        opener = Opener(); opener.value['permission'] = 'Read'
        self.assertEqual(self.run_main(opener)[0], 1)

    def test_pinned_secretspec_resolves_builtin_namespace_without_export(self):
        if not os.environ.get('SECRETSPEC_BIN'):
            self.skipTest('Native contract supplies the pinned SecretSpec executable')
        with tempfile.TemporaryDirectory() as directory:
            native = Path(directory) / 'secretspec'
            native.symlink_to(os.environ['SECRETSPEC_BIN'])
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                       CACHIX_XO_DEVENV_TOKEN=TOKEN, XDG_STATE_HOME=directory)
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(doctor.resolve_token('CACHIX_XO_DEVENV_TOKEN', 'env'), TOKEN)

    def test_provider_failure_does_not_disclose_its_stdout_or_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            native = Path(directory) / 'secretspec'
            native.write_text('#!/bin/sh\nprintf "%s\\n" ' + TOKEN + '\nprintf "%s\\n" ' + TOKEN + ' >&2\nexit 1\n')
            native.chmod(0o755)
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'])
            with patch.dict(os.environ, env, clear=True), self.assertRaises(doctor.DiagnosticError) as caught:
                doctor.resolve_token('CACHIX_XO_DEVENV_TOKEN', 'keyring')
            self.assertNotIn(TOKEN, str(caught.exception))

    def test_provider_timeout_cleans_up_detached_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ready = root / 'ready'; pids = root / 'pids'
            child = ('import os,signal,time; from pathlib import Path; '
                     'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                     f'Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(20)')
            provider = root / 'secretspec'
            provider.write_text('#!' + sys.executable + '\n'
                                'import os,signal,subprocess,sys,time,json\nfrom pathlib import Path\n'
                                'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                                f'child=subprocess.Popen([sys.executable,"-c",{child!r}],start_new_session=True)\n'
                                f'while not Path({str(ready)!r}).exists(): time.sleep(.005)\n'
                                f'Path({str(pids)!r}).write_text(json.dumps([os.getpid(),child.pid]))\n'
                                'time.sleep(20)\n')
            provider.chmod(0o700)
            actual_run = doctor.operations.run
            def short_deadline(args, **kwargs):
                self.assertEqual(kwargs.pop('timeout'), 30)
                return actual_run(args, timeout=.8, **kwargs)
            try:
                with patch.dict(os.environ, {'PATH': directory + os.pathsep + os.environ['PATH']}, clear=True), \
                     patch.object(doctor.operations, 'run', side_effect=short_deadline), \
                     patch.object(doctor.operations, 'KILL_GRACE', .05):
                    started = time.monotonic()
                    with self.assertRaises(doctor.DiagnosticError) as caught:
                        doctor.resolve_token('CACHIX_XO_DEVENV_TOKEN', 'env')
                self.assertEqual(str(caught.exception), 'secret-resolution-timeout')
                self.assertLess(time.monotonic() - started, 3)
                for pid in json.loads(pids.read_text()):
                    self.assert_process_stopped(pid)
            finally:
                for path in (pids, ready):
                    if path.exists():
                        values = json.loads(path.read_text()) if path == pids else [int(path.read_text())]
                        for pid in values:
                            # Fixture-specific command line prevents killing an unrelated reused PID.
                            try:
                                if directory.encode() in Path(f'/proc/{pid}/cmdline').read_bytes():
                                    os.kill(pid, signal.SIGKILL)
                            except (FileNotFoundError, ProcessLookupError):
                                pass

    def assert_process_stopped(self, pid):
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            try:
                state = Path(f'/proc/{pid}/stat').read_text().rpartition(')')[2].split()[0]
            except FileNotFoundError:
                return
            if state == 'Z':
                return
            time.sleep(.01)
        self.fail('Provider descendant survived cleanup')

    def test_cancellation_cleans_up_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ready = root / 'ready'; provider = root / 'secretspec'
            provider.write_text('#!' + sys.executable + '\nimport os,time\nfrom pathlib import Path\n'
                                f'Path({str(ready)!r}).write_text(str(os.getpid()))\ntime.sleep(20)\n')
            provider.chmod(0o700)
            env = {'PATH': directory + os.pathsep + os.environ['PATH'],
                   'PYTHONPATH': str(ROOT / 'ci/decisions')}
            process = subprocess.Popen([sys.executable, str(SOURCE), '--provider', 'env'],
                                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(ready.exists(), 'Fixture provider did not start')
                process.terminate()
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 128 + signal.SIGTERM)
                self.assert_process_stopped(int(ready.read_text()))
                self.assertNotIn(TOKEN.encode(), stdout + stderr)
            finally:
                if process.poll() is None:
                    process.kill(); process.communicate()
                if ready.exists():
                    pid = int(ready.read_text())
                    try:
                        if directory.encode() in Path(f'/proc/{pid}/cmdline').read_bytes():
                            os.kill(pid, signal.SIGKILL)
                    except (FileNotFoundError, ProcessLookupError):
                        pass


if __name__ == '__main__':
    unittest.main()
