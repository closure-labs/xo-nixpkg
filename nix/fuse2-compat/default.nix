# SPDX-License-Identifier: MIT
# Compatibility leaf for XO's upstream fuse-native 2.2.6, not a pkgs.fuse override.
# Adapted from Nixpkgs 3ec636362e1816bc2f0888fa0fa2c69f1bc9e504:
# pkgs/os-specific/linux/fuse/{default,common}.nix (MIT).
{
  lib,
  stdenv,
  fetchFromGitHub,
  fetchpatch,
  util-linux,
  gettext,
  shadow,
  autoreconfHook,
  runtimeShell,
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "fuse";
  version = "2.9.9";

  src = fetchFromGitHub {
    owner = "libfuse";
    repo = "libfuse";
    tag = "fuse-${finalAttrs.version}";
    hash = "sha256-dgjM6M7xk5MHi9xPyCyvF0vq0KM8UCsEYBcMhkrdvfs=";
  };

  strictDeps = true;
  __structuredAttrs = true;

  patches =
    lib.optional (stdenv.hostPlatform.isAarch64 || stdenv.hostPlatform.isLoongArch64)
      (fetchpatch {
        url = "https://github.com/libfuse/libfuse/commit/914871b20a901e3e1e981c92bc42b1c93b7ab81b.patch";
        hash = "sha256-6hqu5npSUN8I7XLZRiCl+b60Sweb1n2ZZz5LroIzkvA=";
      })
    ++ [
      ./fuse2-Do-not-set-FUSERMOUNT_DIR.patch
      (fetchpatch {
        url = "https://gitweb.gentoo.org/repo/gentoo.git/plain/sys-fs/fuse/files/fuse-2.9.9-closefrom-glibc-2-34.patch?id=8a970396fca7aca2d5a761b8e7a8242f1eef14c9";
        hash = "sha256-ELYBW/wxRcSMssv7ejCObrpsJHtOPJcGq33B9yHQII4=";
      })
      ./fuse2-gettext-0.25.patch
    ];

  nativeBuildInputs = [ autoreconfHook gettext ];
  outputs = [ "bin" "out" "dev" "man" ];

  # Preserve Nixpkgs' host-managed privilege boundary. Never install a setuid
  # wrapper ourselves; non-NixOS hosts may provide fusermount through PATH.
  env.NIX_CFLAGS_COMPILE = ''-DFUSERMOUNT_DIR="/run/wrappers/bin"'';

  preConfigure = ''
    substituteInPlace lib/mount_util.c \
      --replace-fail "/bin/mount" "${lib.getBin util-linux}/bin/mount" \
      --replace-fail "/bin/umount" "${lib.getBin util-linux}/bin/umount"
    substituteInPlace util/mount.fuse.c \
      --replace-fail "/bin/sh" "${runtimeShell}"
    export MOUNT_FUSE_PATH=$bin/bin
    export INIT_D_PATH=$TMPDIR/etc/init.d
    export UDEV_RULES_PATH=$TMPDIR/etc/udev/rules.d
    substituteInPlace util/mount.fuse.c \
      --replace-fail '"su"' '"${lib.getBin shadow.su}/bin/su"'
  '';

  # Upstream v2 has no test suite; XO's addon-load/ABI checks remain required.
  doCheck = false;
  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    test -f "$dev/include/fuse/fuse.h"
    test -e "$out/lib/libfuse.so.2"
    cat > "$TMPDIR/fuse2-abi.c" <<'C'
    #define FUSE_USE_VERSION 29
    #include <fuse.h>
    struct fuse *(*xo_fuse_new)(struct fuse_chan *, struct fuse_args *,
      const struct fuse_operations *, size_t, void *) = fuse_new;
    C
    $CC -Werror -D_FILE_OFFSET_BITS=64 -I"$dev/include/fuse" \
      -c "$TMPDIR/fuse2-abi.c" -o "$TMPDIR/fuse2-abi.o"
    runHook postInstallCheck
  '';
  propagatedBuildOutputs = [ "out" ];

  meta = {
    description = "Legacy FUSE 2 compatibility library for Xen Orchestra's upstream Node addon";
    longDescription = ''
      FUSE 2 is end-of-life and was removed from current Nixpkgs. This private
      compatibility leaf retains the last pinned Nixpkgs source and patches
      solely for XO's upstream fuse-native 2.2.6 dependency. It does not make
      FUSE 2 maintained or supported upstream; remove it when XO migrates.
    '';
    homepage = "https://github.com/libfuse/libfuse";
    changelog = "https://github.com/libfuse/libfuse/releases/tag/fuse-${finalAttrs.version}";
    platforms = lib.platforms.linux;
    license = with lib.licenses; [ gpl2Only lgpl21Only ];
    outputsToInstall = [ "bin" ];
  };
})
