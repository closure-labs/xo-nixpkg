{ pkgs }:

let
  yarn = pkgs.yarn.override { nodejs = pkgs.nodejs_22; };
in
{
  packages = [
    pkgs.actionlint
    pkgs.cachix
    pkgs.curl
    pkgs.deadnix
    pkgs.git
    pkgs.gnused
    pkgs.jq
    pkgs.nixd
    pkgs.nixfmt
    pkgs.node-gyp
    pkgs.nodejs_22
    pkgs.pkg-config
    pkgs.python3
    pkgs.shellcheck
    pkgs.statix
    pkgs.valkey
    pkgs.zizmor
    yarn
  ];

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
}
