{
  nixpkgsPath,
  yarnLock,
  normalized ? false,
  hash ? "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
}:

let
  pkgs = import (builtins.toPath nixpkgsPath) { };
  yarnLockPath = builtins.path {
    path = builtins.toPath yarnLock;
    name = "yarn.lock";
  };
  fetchDeps =
    if normalized then
      import ./fetch-normalized-yarn-deps.nix {
        inherit (pkgs) fetchYarnDeps;
      }
    else
      pkgs.fetchYarnDeps;
in
fetchDeps {
  yarnLock = yarnLockPath;
  inherit hash;
}
