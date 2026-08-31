{
  applications,
  self,
  pkgs,
}:

let
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
        ])
        ''
          bash source/tests/policy.sh
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
          grep -F 'rolling-candidate' ${pkgs.lib.getExe applications.prewarmRolling}
          grep -F 'cachix push "$XO_NIXPKG_CACHIX_CACHE_NAME"' \
            source/ci/prewarm-rolling.sh source/ci/publish.sh
          grep -F 'XO_NIXPKG_CACHIX_CACHE_NAME' \
            ${pkgs.lib.getExe applications.prewarmRolling} \
            ${pkgs.lib.getExe applications.publish}
          grep -F 'xo-nixpkg-classify-ci' source/ci/run.sh
          grep -F '/scripts/update.sh' source/ci/update-xo.sh
          grep -F 'xo-nixpkg-update-libvhdi-source' source/ci/update-libvhdi.sh
          grep -F 'xo-nixpkg-trusted-update' source/ci/queue-automation.sh
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
        ])
        ''
          bash source/tests/update-xo.sh
          bash source/tests/update-effects.sh
          bash source/tests/prewarm-rolling.sh
          bash source/tests/update-libvhdi.sh
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
        ])
        ''
          bash source/tests/trusted-update.sh
          bash source/tests/open-update-pr.sh
          bash source/tests/tag-release.sh
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
