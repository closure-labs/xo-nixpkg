{ pkgs, ... }:

{
  name = "xen-orchestra-ce";

  packages = with pkgs; [
    cachix
    curl
    deadnix
    git
    gnused
    jq
    nix-prefetch
    nix-prefetch-github
    nix-update
    nixfmt
    node-gyp
    pkg-config
    python3
    statix
  ];

  languages.javascript = {
    enable = true;
    package = pkgs.nodejs_22;
    yarn = {
      enable = true;
      package = pkgs.yarn.override {
        nodejs = pkgs.nodejs_22;
      };
    };
  };

  languages.typescript.enable = true;

  services.redis = {
    enable = true;
    package = pkgs.valkey;
    bind = "127.0.0.1";
  };

  env = {
    HUSKY = "0";
    DO_NOT_TRACK = "1";
    SCARF_ANALYTICS = "false";
    TURBO_TELEMETRY_DISABLED = "1";
    YARN_PRODUCTION = "false";
    NPM_CONFIG_PRODUCTION = "false";
    npm_config_node_gyp = "${pkgs.node-gyp}/bin/node-gyp";
    npm_config_python = "${pkgs.python3}/bin/python3";
  };

  scripts = {
    build-xo.exec = "nix build .#xen-orchestra-ce";
    check-eval.exec = "nix flake check --accept-flake-config --all-systems --no-build --impure";
    update-release.exec = "./scripts/update.sh --release";
    update-upstream.exec = "./scripts/update.sh --upstream";
  };

  enterShell = ''
    echo "Xen Orchestra CE devenv"
    echo ""
    echo "Common commands:"
    echo "  build-xo        build .#xen-orchestra-ce"
    echo "  check-eval      evaluate flake checks without building"
    echo "  update-release  update to the latest release commit"
    echo "  update-upstream update to the latest upstream source commit"
    echo ""
    echo "Services:"
    echo "  devenv up       start Valkey on 127.0.0.1"
  '';
}
