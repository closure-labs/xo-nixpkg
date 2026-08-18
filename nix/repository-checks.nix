{
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
          zizmor
        ])
        ''
          bash source/tests/policy.sh
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
          bash source/tests/tag-release.sh
        '';

    attribute-validator-fixtures =
      mkCheck "attribute-validator-fixtures"
        (with pkgs; [
          bash
          coreutils
          jq
        ])
        ''
          bash source/tests/flake-attribute-validator.sh
        '';
  };
in
checks
// {
  repository = pkgs.linkFarm "xo-nixpkg-repository-checks" (
    pkgs.lib.mapAttrsToList (name: path: { inherit name path; }) checks
  );
}
