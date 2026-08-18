{
  coreutils,
  jq,
  lib,
  nix,
  writeShellApplication,
}:

writeShellApplication {
  name = "flake-attribute-validator";
  runtimeInputs = [
    coreutils
    jq
    nix
  ];
  text = builtins.readFile ./flake-attribute-validator.sh;
  meta = {
    description = "Validate a pure flake attribute plan and collect independent build failures";
    license = lib.licenses.asl20;
    mainProgram = "flake-attribute-validator";
    platforms = lib.platforms.all;
  };
}
