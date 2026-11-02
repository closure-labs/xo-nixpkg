"""Exercise the installed release wrapper/runtime without publication or credentials."""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ENTRY = 'exec python3 "$XO_NIXPKG_PUBLICATION_CONTROLLER"'


def check_runtime(expected_restore, expected_source):
    source = Path(os.environ['XO_NIXPKG_PUBLICATION_CONTROLLER'])
    if source.resolve() != Path(expected_source).resolve():
        raise AssertionError('Installed controller source differs from expected source')
    spec = importlib.util.spec_from_file_location('installed_publication_controller', source)
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    # Exercise the real subprocess call under the installed parent's runtime PATH.
    # --help exits in argparse before gates, credentials, fetching or Nix restoration.
    result = controller.run('xo-nixpkg-restore-products', '--help',
                            capture_output=True, text=True)
    resolved = shutil.which('xo-nixpkg-restore-products')
    if resolved is None or Path(resolved).resolve() != Path(expected_restore).resolve():
        raise AssertionError('Restore helper resolved outside its declared package')
    if '--materialize-only' not in result.stdout:
        raise AssertionError('Installed restore helper lacks the publication interface')


def check_installed(controller, restore, source):
    controller = Path(controller).resolve()
    text = controller.read_text()
    # Keep the generated wrapper and its actual PATH/prelude, replacing only its
    # final entrypoint in a private test copy. Fail if the wrapper contract changes.
    if text.count(ENTRY) != 1 or text.rstrip().splitlines()[-1] != ENTRY:
        raise AssertionError('Unexpected installed release wrapper entrypoint')
    prefix = text.rsplit(ENTRY, 1)[0]
    with tempfile.TemporaryDirectory(prefix='installed-publication-') as temporary:
        root = Path(temporary)
        # Also launch the unmodified installed command: its early repository guard
        # must work without credentials, network access or the caller's tool PATH.
        env = {'PATH': '/no-ambient-tools', 'HOME': temporary}
        startup = subprocess.run([str(controller)], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=10)
        if startup.returncode != 2 or 'Run this command from' not in startup.stderr:
            raise AssertionError('Installed release command startup guard failed')
        (root / 'flake.nix').write_text('{}\n')
        launcher = root / 'runtime-check'
        launcher.write_text(prefix + 'exec python3 "$TEST_DRIVER" --inside-runtime '
                            '--restore "$EXPECTED_RESTORE" --source "$EXPECTED_SOURCE"\n')
        launcher.chmod(0o755)
        env.update(TEST_DRIVER=str(Path(__file__).resolve()),
                   EXPECTED_RESTORE=str(Path(restore).resolve()),
                   EXPECTED_SOURCE=str(Path(source).resolve()),
                   XO_NIXPKG_SOURCE_ROOT=temporary)
        subprocess.run([str(launcher)], cwd=root, env=env, check=True,
                       capture_output=True, text=True, timeout=15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--controller')
    parser.add_argument('--restore', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--inside-runtime', action='store_true')
    args = parser.parse_args()
    if args.inside_runtime:
        check_runtime(args.restore, args.source)
    else:
        if not args.controller:
            parser.error('--controller is required outside the installed runtime')
        check_installed(args.controller, args.restore, args.source)


if __name__ == '__main__':
    main()
