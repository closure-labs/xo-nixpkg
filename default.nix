{
  lib,
  stdenv,
  fetchYarnDeps,
  yarn,
  yarnConfigHook,
  writableTmpDirAsHomeHook,
  nodejs_22,
  python3,
  node-gyp,
  pkg-config,
  makeWrapper,
  libpng,
  zlib,
  fuse,
  channel,
  docsYarnHash,
  source,
  sourceRev,
  version,
  yarnHash,
}:

let
  platformToolTarballs = import ./nix/yarn-platform-tools.nix {
    inherit lib;
    yarnLock = source + "/yarn.lock";
  };
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
    inherit version;

    # The flake input owns the immutable source revision and NAR hash.
    src = source;

    yarnOfflineCache = fetchNormalizedYarnDeps {
      yarnLock = "${finalAttrs.src}/yarn.lock";
      hash = yarnHash;
    };

    docsYarnOfflineCache = fetchYarnDeps {
      yarnLock = "${finalAttrs.src}/docs/yarn.lock";
      hash = docsYarnHash;
    };

    patches = [ ./nix/patches/xo-server-immutable-source.patch ];

    nativeBuildInputs = [
      writableTmpDirAsHomeHook
      yarn'
      yarnConfigHook'
      nodejs_22
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

    postPatch = ''
      # Keep yarnConfigHook's source/cache lockfile validation aligned with the
      # normalized tarball checksums above.
      cp ${finalAttrs.yarnOfflineCache}/yarn.lock yarn.lock
      cp ${finalAttrs.docsYarnOfflineCache}/yarn.lock docs/yarn.lock

      # Build the root workspaces and documentation from their independent
      # Yarn lockfiles/caches.
      substituteInPlace package.json \
        --replace-fail " && yarn build:doc" ""

      # Provide the immutable source revision without synthesizing a partial
      # Git repository for xo-web's build script.
      substituteInPlace packages/xo-web/package.json \
        --replace-fail 'GIT_HEAD=$(git rev-parse HEAD)' \
                       'GIT_HEAD=${sourceRev}'
      substituteInPlace packages/xo-server/.babelrc.cjs \
        --replace-fail "const { execFileSync } = require('node:child_process')" "" \
        --replace-fail "execFileSync('git', ['rev-parse', '--short', 'HEAD']).toString().trim()" \
                       "'${builtins.substring 0 7 sourceRev}'"

      # TypeScript in newer toolchains infers `Object.entries()` values as unknown.
      # Coerce labels to string for xo-server-openmetrics build compatibility.
      if [ -f packages/xo-server-openmetrics/src/openmetric-formatter.mts ] \
        && grep -q "labels\\[key\\] = value" packages/xo-server-openmetrics/src/openmetric-formatter.mts; then
        substituteInPlace packages/xo-server-openmetrics/src/openmetric-formatter.mts \
          --replace-fail "labels[key] = value" \
                         "labels[key] = typeof value === 'string' ? value : String(value)"
      fi

    '';

    preBuild = ''
              set -euo pipefail

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
        node_modules/fuse-native/build/Release/.deps \
        node_modules/fuse-native/build/Release/build \
        node_modules/fuse-native/build/Release/obj.target \
        node_modules/fuse-native/prebuilds \
        node_modules/leveldown/prebuilds \
        node_modules/fuse-shared-library-linux*/example/build \
        node_modules/fuse-shared-library-linux*/libfuse
      rm -f node_modules/fuse-native/build/Release/libfuse.so

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

    doInstallCheck = true;
    installCheckPhase = ''
      runHook preInstallCheck

      xo_root="$out/libexec/xen-orchestra"
      fuse_native_root="$xo_root/node_modules/fuse-native"
      test -d "$fuse_native_root"

      mapfile -t fuse_addons < <(
        find "$fuse_native_root/build/Release" -maxdepth 1 -type f -name '*.node' -print
      )
      if [ "''${#fuse_addons[@]}" -ne 1 ]; then
        printf 'Expected exactly one rebuilt fuse-native addon, found %s\n' "''${#fuse_addons[@]}" >&2
        printf '%s\n' "''${fuse_addons[@]}" >&2
        exit 1
      fi

      addon_deps="$(ldd "''${fuse_addons[0]}")"
      printf '%s\n' "$addon_deps"
      printf '%s\n' "$addon_deps" | grep -q 'libfuse\.so\.2'
      if printf '%s\n' "$addon_deps" | grep -q 'libfuse3\.so'; then
        echo 'fuse-native unexpectedly links libfuse3' >&2
        exit 1
      fi

      if find "$fuse_native_root" -path '*/prebuilds/*' -print -quit | grep -q .; then
        echo 'fuse-native binary prebuilds remain in the package output' >&2
        exit 1
      fi
      if find "$fuse_native_root" \( -type f -o -type l \) \
        -name 'libfuse*.so*' -print -quit | grep -q .; then
        echo 'fuse-native bundled libfuse remains in the package output' >&2
        exit 1
      fi
      if find "$xo_root/node_modules" \
        -path '*/fuse-shared-library-linux*/libfuse/*' \
        -print -quit | grep -q .; then
        echo 'bundled npm libfuse files remain in the package output' >&2
        exit 1
      fi

      runHook postInstallCheck
    '';

    preFixup = ''
      find "$out/libexec/xen-orchestra" -xtype l -delete || true
    '';

    passthru = {
      inherit channel sourceRev;
      updateScript = ./scripts/update.sh;
    };

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
