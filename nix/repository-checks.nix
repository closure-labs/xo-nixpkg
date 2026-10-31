{
  applications,
  self,
  pkgs,
  securityFixtures,
}:

let
  fuseArchive = pkgs.fetchurl {
    url = "https://registry.yarnpkg.com/fuse-shared-library-linux/-/fuse-shared-library-linux-1.0.1.tgz";
    hash = "sha512-07MQRSobrBKwW4D7oKm0gM2TwgvZWb+gC08JdiYDG4KBTncxk9ssqEDiDMKll8hpseZufsY2w1yc/feOu2DPmQ==";
  };
  fuseArmArchive = pkgs.fetchurl {
    url = "https://registry.yarnpkg.com/fuse-shared-library-linux-arm/-/fuse-shared-library-linux-arm-1.0.0.tgz";
    hash = "sha512-Dj4ssxo1/MKGvOsVWRblSRu+o5F5OJTrVPDkjSyGDU2yKvVnIzQSwy1deiWA0qCcS/Q8iJMlZaCpCcZWSwvoug==";
  };
  yarnCacheFixture =
    pkgs.runCommand "xo-normalized-yarn-cache-fixture"
      {
        nativeBuildInputs = with pkgs; [
          bash
          coreutils
          gnugrep
          gnused
          gnutar
          gzip
        ];
      }
      ''
        bash ${self}/tests/yarn-cache.sh --prepare "$out" ${fuseArchive} ${fuseArmArchive}
      '';

  mkCheck =
    name: nativeBuildInputs: commands:
    pkgs.runCommandLocal "xo-nixpkg-${name}"
      {
        inherit nativeBuildInputs;
      }
      ''
        cp -R ${self} source
        chmod -R u+w source
        ${commands}
        touch "$out"
      '';

  checks = {
    native-runtime-cleanup = mkCheck "native-runtime-cleanup" [ pkgs.python3 ] ''
      PYTHONDONTWRITEBYTECODE=1 python3 source/tests/native-runtime-cleanup.py
    '';

    yarn-cache-fixtures =
      mkCheck "yarn-cache-fixtures"
        (with pkgs; [
          bash
          coreutils
          diffutils
          gnugrep
          gnused
          gnutar
          gzip
          yarn
          fixup-yarn-lock
        ])
        ''
          bash source/tests/yarn-cache.sh ${yarnCacheFixture}
          ${pkgs.lib.concatMapStringsSep "\n"
            (channel: ''
              bash source/tests/yarn-cache.sh --verify \
                ${self.packages.${pkgs.stdenv.hostPlatform.system}.${channel}.yarnOfflineCache}
            '')
            [
              "latest"
              "stable"
              "rolling"
            ]
          }
        '';

    automation-runtime = self.packages.${pkgs.stdenv.hostPlatform.system}.automation-runtime;

    repository-policy =
      mkCheck "repository-policy"
        (with pkgs; [
          actionlint
          coreutils
          findutils
          git
          jq
          ripgrep
          shellcheck
          yq-go
          zizmor
          python3
        ])
        ''
          export SECRETSPEC_BIN=${pkgs.devenv}/bin/secretspec
          test -e ${securityFixtures}
          export XO_NIXPKG_SHARED_FIXTURES_READY=true
          bash source/tests/policy.sh
          bash source/tests/yarn-fetch.sh
        '';

    ci-runtime-fixtures =
      mkCheck "ci-runtime-fixtures"
        (with pkgs; [
          bash
          coreutils
          jq
        ])
        ''
          bash source/tests/ci-runtime.sh
        '';

    application-composition =
      mkCheck "application-composition"
        (with pkgs; [
          gnugrep
          ripgrep
        ])
        ''
          grep -F -- '${pkgs.lib.getExe applications.updateXo} --release' \
            ${pkgs.lib.getExe applications.updateXoRelease}
          grep -F -- '${pkgs.lib.getExe applications.updateXo} --rolling' \
            ${pkgs.lib.getExe applications.updateXoRolling}
          grep -F '${pkgs.diffutils}/bin' ${pkgs.lib.getExe applications.updateXo}
          grep -F 'XO_NIXPKG_REVIEW_PROTOCOL=${../ci/decisions/review_protocol.py}' \
            ${pkgs.lib.getExe applications.trustedUpdate}
          grep -F 'rolling-candidate' ${pkgs.lib.getExe applications.prewarmRolling}
          grep -F 'cachix push "$XO_NIXPKG_CACHIX_CACHE_NAME"' source/ci/publish.sh
          ! rg 'cachix|AUTH_TOKEN' source/ci/prewarm-rolling.sh
          grep -F 'XO_NIXPKG_CACHIX_CACHE_NAME' \
            ${pkgs.lib.getExe applications.publish}
          grep -F 'xo-nixpkg-classify-ci' source/ci/run.sh
          grep -F '/scripts/update.sh' source/ci/update-xo.sh
          grep -F 'xo-nixpkg-update-libvhdi-source' source/ci/update-libvhdi.sh
          grep -F 'xo-nixpkg-trusted-update' source/ci/queue-automation.sh
          grep -F 'determinate-nixd fix hashes --auto-apply' \
            ${pkgs.lib.getExe applications.fixNixHashes}
          grep -F '.channels.latest.version' \
            ${pkgs.lib.getExe applications.tagXoRelease}
          if rg '(ci|scripts)/[A-Za-z0-9._-]+\\.sh' \
            source/ci/run.sh \
            source/ci/update-libvhdi.sh \
            source/ci/queue-automation.sh; then
            echo 'Composed applications must invoke packaged sibling executables' >&2
            exit 1
          fi
        '';

    source-update-fixtures =
      mkCheck "source-update-fixtures"
        (with pkgs; [
          bash
          coreutils
          curl
          gawk
          git
          gnused
          jq
          nix
          python3
        ])
        ''
          bash source/tests/update-xo.sh
          bash source/tests/update-effects.sh
          bash source/tests/prewarm-candidate.sh
          bash source/tests/prewarm-rolling.sh
          bash source/tests/update-libvhdi.sh
          bash source/tests/update-noop.sh
          XO_NIXPKG_UPDATE_XO_WRAPPER=${pkgs.lib.getExe applications.updateXo} \
            bash source/tests/update-noop.sh
        '';

    automation-fixtures =
      mkCheck "automation-fixtures"
        (with pkgs; [
          bash
          coreutils
          git
          gnugrep
          jq
          (python3.withPackages (p: [ p.pyyaml ]))
          nodejs_22
          patch
          findutils
          oras
        ])
        ''
          python3 source/tests/supply-inventory.py
          PYTHONDONTWRITEBYTECODE=1 python3 source/tests/packet-manifest-reproducibility.py \
            --oras ${pkgs.lib.getExe pkgs.oras} --output "$TMPDIR/packet-manifest-proof"
          PYTHONDONTWRITEBYTECODE=1 python3 source/tests/security-applicability.py
          PYTHONDONTWRITEBYTECODE=1 python3 source/tests/security-normalize.py
          PYTHONDONTWRITEBYTECODE=1 python3 source/tests/security-database.py
          PYTHONDONTWRITEBYTECODE=1 python3 source/tests/test_ci_admission.py
          PYTHONDONTWRITEBYTECODE=1 python3 source/tests/test_dependency_update.py
          bash source/tests/security-scan.sh
          node source/tests/isolated-file-restore.mjs
          node source/tests/reproducible-generators.cjs
          PYTHONDONTWRITEBYTECODE=1 python3 source/tests/test_independent_build_proof.py
          bash source/tests/trusted-update.sh
          bash source/tests/fix-nix-hashes.sh
          bash source/tests/open-update-pr.sh
          bash source/tests/tag-release.sh
          bash source/tests/tag-xo-release.sh
          bash source/tests/publication-boundary.sh
          bash source/tests/publish-release.sh
        '';

    plan-runner-fixtures =
      mkCheck "plan-runner-fixtures"
        (with pkgs; [
          bash
          coreutils
          jq
        ])
        ''
          bash source/tests/flake-plan-runner.sh
        '';

    classifier-fixtures =
      mkCheck "classifier-fixtures"
        (with pkgs; [
          bash
          coreutils
          git
          gnugrep
          gnused
          jq
        ])
        ''
          bash source/tests/classifier.sh
        '';
  };
in
checks
// {
  repository = pkgs.linkFarm "xo-nixpkg-repository-checks" (
    pkgs.lib.mapAttrsToList (name: path: { inherit name path; }) checks
  );
}
