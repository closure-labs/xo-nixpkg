let
  valueOr =
    name: fallback:
    let
      value = builtins.getEnv name;
    in
    if value == "" then fallback else value;
  sourceRoot = valueOr "XO_NIXPKG_SOURCE_ROOT" (builtins.getEnv "PWD");
  flakeRef = valueOr "XO_NIXPKG_FLAKE_REF" "git+file://${sourceRoot}";
  system = valueOr "XO_NIXPKG_CI_SYSTEM" builtins.currentSystem;
  sourceAttribute = "lib.ciWorkflows.${system}";
  flake = builtins.getFlake flakeRef;
in
flake.lib.prepareCiWorkflow {
  workflow = flake.lib.ciWorkflows.${system};
  inherit system sourceAttribute;
  event = {
    name = valueOr "GITHUB_EVENT_NAME" "local";
    ref = valueOr "GITHUB_REF" "local";
  };
}
