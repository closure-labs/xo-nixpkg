"""Lightweight tests of the installed-wrapper regression harness; no Nix builds."""
import importlib.util
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    'installed_runtime_fixture', Path(__file__).with_name('installed-publication-runtime.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class InstalledRuntimeTests(unittest.TestCase):
    def fixture(self, include_helper=True, valid_interface=True, duplicate_entry=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools, helpers = root / 'tools', root / 'helpers'
            tools.mkdir()
            helpers.mkdir()
            (tools / 'python3').symlink_to(sys.executable)
            helper = helpers / 'xo-nixpkg-restore-products'
            helper.write_text('#!' + sys.executable + '\nprint(' +
                              repr('--materialize-only' if valid_interface else 'wrong interface') + ')\n')
            helper.chmod(0o755)
            source = root / 'controller.py'
            source.write_text('import subprocess\ndef run(*args, **kwargs):\n'
                              '    return subprocess.run(args, check=True, **kwargs)\n')
            controller = root / 'xo-nixpkg-publication-controller'
            path = str(tools) + (':' + str(helpers) if include_helper else '')
            controller.write_text('#!' + shutil.which('bash') + '\nset -euo pipefail\n'
                'export PATH=' + shlex.quote(path) + '\n'
                'repo_root="${XO_NIXPKG_SOURCE_ROOT:-$PWD}"\n'
                'if [[ ! -f "$repo_root/flake.nix" ]]; then\n'
                '  echo "Run this command from the xo-nixpkg repository root" >&2\n'
                '  exit 2\nfi\n'
                'cd "$repo_root"\n'
                'export XO_NIXPKG_PUBLICATION_CONTROLLER=' + shlex.quote(str(source)) + '\n' +
                (M.ENTRY + '\n' if duplicate_entry else '') + M.ENTRY + '\n')
            controller.chmod(0o755)
            M.check_installed(controller, helper, source)

    def test_declared_helper_is_invoked_in_installed_parent_runtime(self):
        self.fixture()

    def test_transitive_closure_without_path_dependency_reproduces_failure(self):
        # The helper exists on disk but is absent from the parent's runtime PATH.
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            self.fixture(include_helper=False)
        self.assertIn('FileNotFoundError', raised.exception.stderr)

    def test_wrong_helper_interface_is_rejected(self):
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            self.fixture(valid_interface=False)
        self.assertIn('lacks the publication interface', raised.exception.stderr)

    def test_wrapper_layout_change_fails_closed(self):
        with self.assertRaisesRegex(AssertionError, 'entrypoint'):
            self.fixture(duplicate_entry=True)


if __name__ == '__main__':
    unittest.main()
