# One locked engine for native history scans and pure scanner fixtures.
{ pkgs }:
let
  package = pkgs.gitleaks.overrideAttrs (_: { tags = [ ]; });
in
assert package.version == "8.30.1";
assert package.src.outputHash == "sha256-PpMquYyXNN6KFwN/efY5+gr+4IhSKPoAy2M/rcqfW5k=";
{
  inherit package;
  identity = pkgs.writeText "xo-secret-scanner-identity.json" (builtins.toJSON {
    schema = 1;
    name = "gitleaks";
    version = package.version;
    regexpEngine = "go-stdlib";
    executable = "${package}/bin/gitleaks";
  });
}
