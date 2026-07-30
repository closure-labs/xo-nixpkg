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
  git,
  python3,
  node-gyp,
  pkg-config,
  makeWrapper,
  libpng,
  zlib,
  fuse,
}:

let
  platformToolTarballs = import ./nix/platform-tools.nix;
  platformToolTarballsForHost = platformToolTarballs.${stdenv.hostPlatform.system} or null;

  mkYarnCacheBinary =
    yarnOfflineCache:
    {
      pname,
      version,
      tarball,
      path,
      binaryName,
    }:
    stdenv.mkDerivation {
      inherit pname version;
      src = "${yarnOfflineCache}/${tarball}";
      dontUnpack = true;
      installPhase = ''
        runHook preInstall

        mkdir -p "$out/bin"
        tar -xzf "$src" -O "${path}" > "$out/bin/${binaryName}"
        chmod +x "$out/bin/${binaryName}"

        runHook postInstall
      '';
    };

  mkYarnCacheFile =
    yarnOfflineCache:
    {
      pname,
      version,
      tarball,
      path,
      fileName,
    }:
    stdenv.mkDerivation {
      inherit pname version;
      src = "${yarnOfflineCache}/${tarball}";
      dontUnpack = true;
      installPhase = ''
        runHook preInstall

        mkdir -p "$out"
        tar -xzf "$src" -O "${path}" > "$out/${fileName}"

        runHook postInstall
      '';
    };

  mkPlatformTools =
    yarnOfflineCache:
    if platformToolTarballsForHost == null then
      { }
    else
      let
        mkBinary = mkYarnCacheBinary yarnOfflineCache;
        mkFile = mkYarnCacheFile yarnOfflineCache;
      in
      (lib.optionalAttrs ((platformToolTarballsForHost.esbuild or null) != null) {
        esbuild = mkBinary {
          pname = "esbuild-xen-orchestra";
          binaryName = "esbuild";
          inherit (platformToolTarballsForHost.esbuild) version tarball path;
        };
      })
      // (lib.optionalAttrs ((platformToolTarballsForHost.turbo or null) != null) {
        turbo = mkBinary {
          pname = "turbo-xen-orchestra";
          binaryName = "turbo";
          inherit (platformToolTarballsForHost.turbo) version tarball path;
        };
      })
      // (lib.optionalAttrs ((platformToolTarballsForHost.rollup or null) != null) {
        rollupPackageBase = platformToolTarballsForHost.rollup.packageBase;
        rollupNative = mkFile {
          pname = "rollup-native-xen-orchestra";
          fileName = "rollup.${platformToolTarballsForHost.rollup.packageBase}.node";
          inherit (platformToolTarballsForHost.rollup) version tarball path;
        };
      });

  fetchNormalizedYarnDeps = import ./nix/fetch-normalized-yarn-deps.nix {
    inherit fetchYarnDeps;
  };
  # Keep Yarn classic on the same Node major as Xen Orchestra. nixpkgs' default
  # yarn may be shebanged to a newer Node, which emits DEP0169 during install.
  yarn' = yarn.override {
    nodejs = nodejs_22;
  };
  yarnConfigHook' = yarnConfigHook.override {
    nodejs = nodejs_22;
    yarn = yarn';
  };
  yarnBuildHook' = yarnBuildHook.override {
    nodejs = nodejs_22;
    yarn = yarn';
  };
in
stdenv.mkDerivation (
  finalAttrs:
  let
    platformTools = mkPlatformTools finalAttrs.yarnOfflineCache;
  in
  {
    pname = "xen-orchestra-ce";
    version = "6.7.0";

    # Xen Orchestra doesn't use git tags for releases; versions are indicated
    # in commit messages like "feat: release 6.3.3".
    src = fetchFromGitHub {
      owner = "vatesfr";
      repo = "xen-orchestra";
      rev = "1a795970f9c60396967d9510e3d2a29b56f2da1d";
      hash = "sha256-myMFRgZeZCXcyQHYcoucEFSOuCNzHXiWua3ciuH5jds=";
    };

    yarnOfflineCache = fetchNormalizedYarnDeps {
      yarnLock = "${finalAttrs.src}/yarn.lock";
      hash = "sha256-8qv/ak3fYY2ODpWN3WZO5wrXokiK6CH8vGq49cmZlvA=";
    };

    docsYarnOfflineCache = fetchYarnDeps {
      yarnLock = "${finalAttrs.src}/docs/yarn.lock";
      hash = "sha256-v5h1lb7zlW926EKpjK+c5CTtqczvgMDZhyQzkWdattE=";
    };

    nativeBuildInputs = [
      writableTmpDirAsHomeHook
      yarn'
      yarnConfigHook'
      yarnBuildHook'
      nodejs_22
      git
      python3
      node-gyp
      pkg-config
      makeWrapper
    ]
    ++ lib.optionals (platformTools ? esbuild) [
      platformTools.esbuild
    ]
    ++ lib.optionals (platformTools ? turbo) [
      platformTools.turbo
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
      DO_NOT_TRACK = "1";
      SCARF_ANALYTICS = "false";
      TURBO_TELEMETRY_DISABLED = "1";
      YARN_PRODUCTION = "false";
      NPM_CONFIG_PRODUCTION = "false";
      npm_config_nodedir = "${nodejs_22}";
      npm_config_node_gyp = "${node-gyp}/bin/node-gyp";
      npm_config_python = "${python3}/bin/python3";
      LD_LIBRARY_PATH = lib.makeLibraryPath [ fuse ];
    }
    // lib.optionalAttrs (platformTools ? esbuild) {
      ESBUILD_BINARY_PATH = "${platformTools.esbuild}/bin/esbuild";
    }
    // lib.optionalAttrs (platformTools ? turbo) {
      TURBO_BINARY_PATH = "${platformTools.turbo}/bin/turbo";
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
      cp ${finalAttrs.docsYarnOfflineCache}/yarn.lock docs/yarn.lock

      # Build the root workspaces and documentation from their independent
      # Yarn lockfiles/caches.
      substituteInPlace package.json \
        --replace-fail " && yarn build:doc" ""

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

    preBuild = ''
              set -euo pipefail

              patchShebangs node_modules

              vue_tsc_target="$(readlink -f node_modules/.bin/vue-tsc 2>/dev/null || true)"
              if [ -z "$vue_tsc_target" ]; then
                echo "ERROR: Cannot find vue-tsc in node_modules/.bin" >&2
                exit 1
              fi

              mkdir -p @xen-orchestra/web/node_modules/.bin
              rm -f @xen-orchestra/web/node_modules/.bin/vue-tsc
              makeWrapper ${nodejs_22}/bin/node @xen-orchestra/web/node_modules/.bin/vue-tsc \
                --add-flags "$vue_tsc_target"

          if [ -f node_modules/fuse-shared-library-linux/index.js ]; then
            node -e '
          const fs = require("node:fs")
          const q = String.fromCharCode(39)

          const file = "node_modules/fuse-shared-library-linux/index.js"
          let source = fs.readFileSync(file, "utf8")

          function replace(needle, replacement) {
            if (!source.includes(needle)) {
              throw new Error("cannot find expected fuse-shared-library-linux text: " + needle)
            }
            source = source.replace(needle, replacement)
          }

          replace(
            "const FUSE = path.join(__dirname, " + q + "libfuse" + q + ")",
            "const FUSE = " + q + "${lib.getBin fuse}" + q
          )
          replace(
            "const lib = path.join(FUSE, " + q + "lib/libfuse.so" + q + ")",
            "const lib = " + q + "${lib.getLib fuse}/lib/libfuse.so" + q
          )
          replace(
            "const include = path.join(FUSE, " + q + "include" + q + ")",
            "const include = " + q + "${fuse.dev}/include/fuse" + q
          )

          source = source.replace(
            /function beforeMount \(cb\) {[\s\S]*?\n}\n\nfunction beforeUnmount/,
            "function beforeMount (cb) {\n  if (!cb) cb = noop\n  process.nextTick(cb)\n}\n\nfunction beforeUnmount"
          )
          source = source.replace(
            /function configure \(cb\) {[\s\S]*?\n}\n\nfunction isConfigured/,
            "function configure (cb) {\n  if (!cb) cb = noop\n  process.nextTick(cb)\n}\n\nfunction isConfigured"
          )
          source = source.replace(
            /function isConfigured \(cb\) {[\s\S]*?\n}\n\nfunction runAll/,
            "function isConfigured (cb) {\n  process.nextTick(cb, null, true)\n}\n\nfunction runAll"
          )

          fs.writeFileSync(file, source)
          '
          fi

              ${lib.optionalString (platformTools ? rollupNative) ''
                if [ -d node_modules/rollup/dist ]; then
                  cp ${platformTools.rollupNative}/rollup.${platformTools.rollupPackageBase}.node \
                    node_modules/rollup/dist/
                fi
              ''}

              node_gyp_build="$PWD/node_modules/.bin/node-gyp-build"
              if [ ! -x "$node_gyp_build" ]; then
                echo "ERROR: Cannot find node-gyp-build in node_modules/.bin" >&2
                exit 1
              fi

              rebuildNodeModuleFromSource() {
                local modulePath="$1"
                [ -d "$modulePath" ] || return 0

                echo "rebuilding $modulePath from source"
                (
                  cd "$modulePath"
                  rm -rf build
                  npm_config_build_from_source=true \
                  npm_config_nodedir="${nodejs_22}" \
                  npm_config_node_gyp="${node-gyp}/bin/node-gyp" \
                  npm_config_python="${python3}/bin/python3" \
                    "$node_gyp_build"
                )
              }

              rebuildNodeModuleFromSource node_modules/fuse-native
              rebuildNodeModuleFromSource node_modules/argon2
              rebuildNodeModuleFromSource node_modules/leveldown

      rm -rf \
        node_modules/argon2/prebuilds \
        node_modules/fuse-native/prebuilds \
        node_modules/leveldown/prebuilds \
        node_modules/fuse-shared-library-linux*/example/build \
        node_modules/fuse-shared-library-linux*/libfuse

              if [ -f node_modules/http-proxy/lib/http-proxy/index.js ] \
                && grep -q "require('util')._extend" node_modules/http-proxy/lib/http-proxy/index.js; then
                  substituteInPlace node_modules/http-proxy/lib/http-proxy/index.js \
                    --replace-fail "extend    = require('util')._extend," \
                                   "extend    = Object.assign,"
                fi

    '';

    buildPhase = ''
      runHook preBuild
      TURBO_CONCURRENCY=1 yarn --offline run build

      (
        cd docs
        export HOME="$(mktemp -d)"
        yarn config --offline set yarn-offline-mirror "${finalAttrs.docsYarnOfflineCache}"
        fixup-yarn-lock yarn.lock
        yarn install \
          --frozen-lockfile \
          --force \
          --production=false \
          --ignore-engines \
          --ignore-platform \
          --ignore-scripts \
          --no-progress \
          --non-interactive \
          --offline
        patchShebangs node_modules
        yarn --offline run build:xo-server
      )

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

      mkdir -p $out/libexec/xen-orchestra/docs
      cp -a docs/build-embed $out/libexec/xen-orchestra/docs/

      makeWrapper ${nodejs_22}/bin/node $out/bin/xo-server \
        --chdir $out/libexec/xen-orchestra \
        --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath [ fuse ]} \
        --prefix PATH : ${lib.makeBinPath [ (lib.getBin fuse) ]} \
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
  }
)
