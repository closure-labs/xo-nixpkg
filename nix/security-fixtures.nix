{ pkgs, source }:
let
  secretScanner = import ./secret-scanner.nix { inherit pkgs; };
in
pkgs.runCommandLocal "xo-nixpkg-security-fixtures"
  {
    nativeBuildInputs = with pkgs; [
      bash
      coreutils
      git
      secretScanner.package
      jq
      findutils
      ripgrep
      shellcheck
      yq-go
      actionlint
      zizmor
      python3
    ];
  }
  ''
    cp -R ${source} source
    chmod -R u+w source
    cd source
    export PYTHONDONTWRITEBYTECODE=1
    export SCANNER_FIXTURE_ENGINE=${secretScanner.package}/bin/gitleaks
    export SECRETSPEC_BIN=${pkgs.devenv}/bin/secretspec
    bash ci/security-fixtures.sh
    touch "$out"
  ''
