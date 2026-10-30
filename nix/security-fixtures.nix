{ pkgs, source }:
pkgs.runCommandLocal "xo-nixpkg-security-fixtures"
  {
    nativeBuildInputs = with pkgs; [
      bash
      coreutils
      git
      jq
      findutils
      ripgrep
      shellcheck
      yq-go
      actionlint
      zizmor
      (python3.withPackages (p: [ p.pyyaml ]))
    ];
  }
  ''
    cp -R ${source} source
    chmod -R u+w source
    cd source
    export PYTHONDONTWRITEBYTECODE=1
    export SECRETSPEC_BIN=${pkgs.devenv}/bin/secretspec
    bash ci/security-fixtures.sh
    touch "$out"
  ''
