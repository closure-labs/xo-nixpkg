# SPDX-License-Identifier: Apache-2.0
{
  autoreconfHook,
  fuse3,
  lib,
  pkg-config,
  source,
  stdenv,
  zlib,
}:

stdenv.mkDerivation {
  pname = "libvhdi";
  version = source.version;
  src = source;

  nativeBuildInputs = [
    autoreconfHook
    pkg-config
  ];

  buildInputs = [
    fuse3
    zlib
  ];

  configureFlags = [
    "--enable-python=no"
    "--with-libfuse=yes"
    "--enable-multi-threading-support"
    "--enable-wide-character-type"
  ];

  enableParallelBuilding = true;
  doCheck = true;
  doInstallCheck = true;

  preCheck = ''
    patchShebangs tests
  '';

  installCheckPhase = ''
    runHook preInstallCheck

    test -f "$out/lib/libvhdi.so"
    test -x "$out/bin/vhdiinfo"
    test -x "$out/bin/vhdimount"

    "$out/bin/vhdiinfo" -V
    "$out/bin/vhdimount" -V

    vhdimount_deps="$(ldd "$out/bin/vhdimount")"
    printf '%s\n' "$vhdimount_deps"
    printf '%s\n' "$vhdimount_deps" | grep -q 'libfuse3\.so'
    if printf '%s\n' "$vhdimount_deps" | grep -q 'libfuse\.so'; then
      echo "vhdimount unexpectedly links libfuse2" >&2
      exit 1
    fi

    runHook postInstallCheck
  '';

  passthru.fuseBackend = "fuse3";

  meta = {
    description = "Library and tools to access VHD and VHDX images";
    homepage = "https://github.com/libyal/libvhdi";
    license = lib.licenses.lgpl3Plus;
    platforms = lib.platforms.linux;
    mainProgram = "vhdiinfo";
    maintainers = [
      {
        name = "Dale Morgan";
        email = "mail@dalemorgan.us";
        github = "declarative-dale";
      }
    ];
  };
}
