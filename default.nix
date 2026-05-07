{
  lib,
  stdenv,
  fetchFromGitHub,
  fetchYarnDeps,
  yarn,
  yarnConfigHook,
  yarnBuildHook,
  writableTmpDirAsHomeHook,
  nodejs_22,
  esbuild,
  git,
  python3,
  pkg-config,
  makeWrapper,
  libpng,
  zlib,
  fuse,
}:

let
  fetchNormalizedYarnDeps = import ./nix/fetch-normalized-yarn-deps.nix {
    inherit fetchYarnDeps;
  };
in
stdenv.mkDerivation (finalAttrs: {
  pname = "xen-orchestra-ce";
  version = "6.4.1";

  # Xen Orchestra doesn't use git tags for releases; versions are indicated
  # in commit messages like "feat: release 6.3.3".
  src = fetchFromGitHub {
    owner = "vatesfr";
    repo = "xen-orchestra";
    rev = "7e144234b970b006f4d96ee82be271d1c16e0de5";
    hash = "sha256-8coyJNLdte4e5DDP/+byFfag3ticALL0xmALhlrtPg8=";
  };

  yarnOfflineCache = fetchNormalizedYarnDeps {
    yarnLock = "${finalAttrs.src}/yarn.lock";
    hash = "sha256-WMu6U3+8tHmw7Fz81MhieNcoojnSAccXIYLOQC7d4+o=";
  };

  nativeBuildInputs = [
    writableTmpDirAsHomeHook
    yarn
    yarnConfigHook
    yarnBuildHook
    nodejs_22
    esbuild
    git
    python3
    pkg-config
    makeWrapper
  ];

  buildInputs = [
    # libfuse2 for fuse-native/@vates/fuse-vhd.
    fuse
    zlib
    libpng
    stdenv.cc.cc.lib
  ];

  env = {
    HUSKY = "0";
    CI = "1";
    YARN_PRODUCTION = "false";
    NPM_CONFIG_PRODUCTION = "false";
    LD_LIBRARY_PATH = lib.makeLibraryPath [ fuse ];
  };

  yarnInstallFlags = [
    "--offline"
    "--frozen-lockfile"
    "--non-interactive"
    "--ignore-engines"
    "--production=false"
  ];

  yarnFlags = finalAttrs.yarnInstallFlags;

  postPatch = ''
    # Keep yarnConfigHook's source/cache lockfile validation aligned with the
    # normalized tarball checksums above.
    cp ${finalAttrs.yarnOfflineCache}/yarn.lock yarn.lock

    # Patch SMB handler to include missing createReadStream import
    if [ -f packages/xo-server/src/xo-mixins/storage/smb.js ] \
      && grep -q "const { join } = require('path')" packages/xo-server/src/xo-mixins/storage/smb.js; then
      substituteInPlace packages/xo-server/src/xo-mixins/storage/smb.js \
        --replace-fail "const { join } = require('path')" \
                       "const { join } = require('path'); const { createReadStream } = require('fs')"
    fi

    # Fix missing createReadStream import in FS module
    if [ -f @xen-orchestra/fs/src/index.js ] \
      && grep -q "const { asyncIterableToStream }" @xen-orchestra/fs/src/index.js \
      && ! grep -q "createReadStream" @xen-orchestra/fs/src/index.js; then
      substituteInPlace @xen-orchestra/fs/src/index.js \
        --replace-fail "const { asyncIterableToStream } = require('./_asyncIterableToStream')" \
                       "const { createReadStream } = require('node:fs');\nconst { asyncIterableToStream } = require('./_asyncIterableToStream')"
    fi

    # TypeScript in newer toolchains infers `Object.entries()` values as unknown.
    # Coerce labels to string for xo-server-openmetrics build compatibility.
    if [ -f packages/xo-server-openmetrics/src/openmetric-formatter.mts ] \
      && grep -q "labels\\[key\\] = value" packages/xo-server-openmetrics/src/openmetric-formatter.mts; then
      substituteInPlace packages/xo-server-openmetrics/src/openmetric-formatter.mts \
        --replace-fail "labels[key] = value" \
                       "labels[key] = typeof value === 'string' ? value : String(value)"
    fi

    # Create minimal .git directory for git rev-parse during build
    if [ ! -e .git ]; then
      mkdir -p .git/objects .git/refs
      cat > .git/config <<EOF
    [core]
        repositoryformatversion = 0
        filemode = true
        bare = false
    EOF
      echo "${finalAttrs.src.rev}" > .git/HEAD
    fi
  '';

  postConfigure = ''
    patchShebangs node_modules
  '';

  preBuild = ''
    set -euo pipefail

    vite_target="$(readlink -f node_modules/.bin/vite 2>/dev/null || true)"
    vue_tsc_target="$(readlink -f node_modules/.bin/vue-tsc 2>/dev/null || true)"

    if [ -z "$vite_target" ]; then
      echo "ERROR: Cannot find vite in node_modules/.bin" >&2
      exit 1
    fi
    if [ -z "$vue_tsc_target" ]; then
      echo "ERROR: Cannot find vue-tsc in node_modules/.bin" >&2
      exit 1
    fi

    mkToolWrappers() {
      local pkg="$1"
      [ -d "$pkg" ] || return 0

      mkdir -p "$pkg/node_modules/.bin"

      cat > "$pkg/node_modules/.bin/vite" <<WRAPPER
    #!${stdenv.shell}
    exec ${nodejs_22}/bin/node "$vite_target" "\$@"
    WRAPPER
      chmod +x "$pkg/node_modules/.bin/vite"

      cat > "$pkg/node_modules/.bin/vue-tsc" <<WRAPPER
    #!${stdenv.shell}
    exec ${nodejs_22}/bin/node "$vue_tsc_target" "\$@"
    WRAPPER
      chmod +x "$pkg/node_modules/.bin/vue-tsc"
    }

    mkToolWrappers "@xen-orchestra/web"
    mkToolWrappers "packages/xo-web"
    mkToolWrappers "xo-web"
  '';

  buildPhase = ''
    runHook preBuild
    TURBO_CONCURRENCY=1 yarn --offline run build
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out/libexec/xen-orchestra
    mkdir -p $out/bin

    cp -a packages node_modules package.json yarn.lock $out/libexec/xen-orchestra/

    for dir in @xen-orchestra @vates scripts; do
      if [ -d "$dir" ]; then
        cp -a "$dir" $out/libexec/xen-orchestra/
      fi
    done

    makeWrapper ${nodejs_22}/bin/node $out/bin/xo-server \
      --chdir $out/libexec/xen-orchestra \
      --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath [ fuse ]} \
      --add-flags "packages/xo-server/dist/cli.mjs"

    runHook postInstall
  '';

  preFixup = ''
    find "$out/libexec/xen-orchestra" -xtype l -delete || true
  '';

  passthru.updateScript = ./scripts/update.sh;

  meta = {
    description = "Web interface for Xen Orchestra - XenServer/XCP-ng management";
    longDescription = ''
      Xen Orchestra provides a web-based interface for managing XenServer and
      XCP-ng infrastructure. It offers VM lifecycle management, backup solutions,
      continuous replication, and disaster recovery features.

      This package builds the Community Edition from source.
    '';
    homepage = "https://xen-orchestra.com";
    changelog = "https://github.com/vatesfr/xen-orchestra/commits/master";
    license = lib.licenses.agpl3Only;
    maintainers = [
      {
        name = "Dale Morgan";
        email = "mail@dalemorgan.us";
      }
    ];
    platforms = lib.platforms.linux;
    mainProgram = "xo-server";
  };
})
