{
  coreutils,
  jq,
  lib,
  nix,
  writeShellApplication,
}:

writeShellApplication {
  name = "flake-plan-runner";
  runtimeInputs = [
    coreutils
    jq
    nix
  ];
  text = builtins.readFile ./flake-plan-runner.sh;
  meta = {
    description = "Validate and execute schema-v2 pure flake CI plans";
    license = lib.licenses.asl20;
    mainProgram = "flake-plan-runner";
    platforms = lib.platforms.all;
  };
}
