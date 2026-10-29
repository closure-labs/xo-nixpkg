# SPDX-License-Identifier: Apache-2.0
"""Keep the upstream FUSE 2 exception private, pinned, and ABI checked."""
import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEAF = ROOT / 'nix/fuse2-compat'


class FuseCompatibility(unittest.TestCase):
    def test_canonical_source_and_patch_pins_are_preserved(self):
        expression = (LEAF / 'default.nix').read_text()
        for value in ('version = "2.9.9"', 'owner = "libfuse"', 'repo = "libfuse"',
                      'sha256-dgjM6M7xk5MHi9xPyCyvF0vq0KM8UCsEYBcMhkrdvfs=',
                      '914871b20a901e3e1e981c92bc42b1c93b7ab81b',
                      'sha256-6hqu5npSUN8I7XLZRiCl+b60Sweb1n2ZZz5LroIzkvA=',
                      '8a970396fca7aca2d5a761b8e7a8242f1eef14c9',
                      'sha256-ELYBW/wxRcSMssv7ejCObrpsJHtOPJcGq33B9yHQII4=',
                      'stdenv.hostPlatform.isAarch64 || stdenv.hostPlatform.isLoongArch64'):
            self.assertIn(value, expression)
        for name, digest in {
            'fuse2-Do-not-set-FUSERMOUNT_DIR.patch': '8c569e35a405e581ee451806b77d9abc571304b80d4381c36c817c98048779a3',
            'fuse2-gettext-0.25.patch': '71e8462076d5787af8b8835be6d9c34290af3e981b21790e877ba3c3730297d5',
        }.items():
            self.assertEqual(hashlib.sha256((LEAF / name).read_bytes()).hexdigest(), digest)
        self.assertIn('Nixpkgs/NixOS contributors', (LEAF / 'COPYING').read_text())

    def test_only_xo_receives_compatibility_dependency(self):
        flake = (ROOT / 'flake.nix').read_text()
        self.assertEqual(flake.count('pkgs.callPackage ./nix/fuse2-compat'), 1)
        self.assertIn('fuse2 = pkgs.callPackage ./nix/fuse2-compat { };', flake)
        vhdi = (ROOT / 'nix/libvhdi.nix').read_text()
        self.assertIn('    fuse3\n', vhdi)
        self.assertNotIn('    fuse2\n', vhdi)
        xo = (ROOT / 'default.nix').read_text()
        self.assertIn('lib.versions.major fuse2.version == "2"', xo)
        self.assertNotIn('  fuse,', xo)
        self.assertIn('${lib.getDev fuse2}/include/fuse', xo)
        self.assertIn('${lib.getLib fuse2}/lib/libfuse.so', xo)
        self.assertNotIn('include/fuse3', xo)

    def test_runtime_feature_and_security_checks_remain(self):
        xo = (ROOT / 'default.nix').read_text()
        for value in ('rebuildNodeModuleFromSource node_modules/fuse-native',
                      'require(root + "/node_modules/fuse-native")',
                      "grep -q 'libfuse\\.so\\.2'", "grep -q 'libfuse3\\.so'",
                      'fuse-native binary prebuilds remain', 'fuse-native bundled libfuse remains'):
            self.assertIn(value, xo)
        expression = (LEAF / 'default.nix').read_text()
        self.assertIn('#define FUSE_USE_VERSION 29', expression)
        self.assertIn('struct fuse_chan *', expression)
        self.assertIn('test -e "$out/lib/libfuse.so.2"', expression)
        self.assertNotIn('chmod u+s', expression)
        self.assertIn('FUSERMOUNT_DIR="/run/wrappers/bin"', expression)
        self.assertIn('end-of-life', (LEAF / 'README.md').read_text())

    def test_leaf_changes_validate_all_xo_channels_not_an_unrelated_libvhdi_abi(self):
        cfg = json.loads((ROOT / 'ci/classifier.json').read_text())
        for path in ('nix/fuse2-compat/default.nix', 'nix/fuse2-compat/fuse2-gettext-0.25.patch'):
            rule = next(r for r in cfg['pathRules'] if re.search(r['pattern'], path))
            self.assertTrue({'xo-latest', 'xo-stable', 'xo-rolling', 'xo-fuse-linkage'} <= set(rule['validation']))


if __name__ == '__main__':
    unittest.main()
