{ pkgs, config, ... }:

let
  developmentEnvironment = import ./nix/development-environment.nix { inherit pkgs; };
in
{
  # Devenv resolves the public URL and signing key for this cache name and
  # applies them as extra-substituters and extra-trusted-public-keys.
  cachix.pull = [ "xen-orchestra-ce" ];

  inherit (developmentEnvironment) packages;
  env =
    (
      if config.packages == [ ] then developmentEnvironment.controllerEnv else developmentEnvironment.env
    )
    // {
      # Pin the same trust root for Nix commands run from inside the shell.
      NIX_CONFIG = ''
        extra-substituters = https://xen-orchestra-ce.cachix.org
        extra-trusted-public-keys = xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E=
      '';
    };

  tasks = {
    "ci:classify".exec = "nix run .#classify-ci -- \"$GITHUB_OUTPUT\"";
    "ci:validate".exec = "nix run .#ci";
    "ci:trusted-validate".exec = "nix run .#build-reuse -- validate";
    "ci:restore-builds".exec = "nix run .#build-reuse -- restore";
    "ci:verdict".exec = "nix run .#ci-verdict";
    "ci:security-lint".exec = "nix run .#security-lint";
    "ci:consumer-probe".exec = "nix run .#consumer-probe";
    "ci:repository-audit".exec = ''
      export XO_NIXPKG_AUDIT_NIX_BIN="$(command -v nix)"
      nix run .#repository-audit
    '';
    "security:audit-policy".exec = "nix run .#audit-policy";
    "security:review".exec = "nix run .#security-scan";
    "security:refresh".exec = "nix run .#refresh-products";
    "security:fetch-rescan".exec = "nix run .#fetch-evidence";
    "security:collect".exec = "nix run .#decision-collect";
    "security:authority".exec = "nix run .#decision-authority";
    "security:inspect".exec = "nix run .#inspect-qualification";
    "security:resume".exec = "nix run .#reconcile-retained";
    "security:qualify".exec = "nix run .#qualify-products";
    "security:readiness".exec = "nix run .#decision-readiness";
    "security:reconcile".exec = "nix run .#decision-reconcile";
    "release:resume".exec = "nix run .#publication-controller";
    "release:fetch".exec = "nix run .#fetch-evidence";
    "release:publish".exec = "nix run .#publish";
    "release:tag-project".exec = "nix run .#tag-release";
    "release:tag-xo".exec = "nix run .#tag-xo-release";
    "release:github".exec = "nix run .#publish-release";
    "update:xo-release".exec = "nix run .#update-xo-release -- \"$GITHUB_OUTPUT\"";
    "update:xo-rolling".exec = "nix run .#update-xo-rolling -- \"$GITHUB_OUTPUT\"";
    "update:runtime-realize".exec = "nix run .#prewarm-runtime -- \"$GITHUB_OUTPUT\"";
    "update:release-realize".exec =
      "nix run .#prewarm-release-candidate -- \"$CHANGED_CHANNELS\" \"$GITHUB_OUTPUT\"";
    "update:rolling-realize".exec = "nix run .#prewarm-rolling-candidate -- \"$GITHUB_OUTPUT\"";
    "update:libvhdi".exec = "nix run .#update-libvhdi -- \"$GITHUB_OUTPUT\"";
    "update:flake-lock".exec = "nix run .#update-flake-lock -- \"$GITHUB_OUTPUT\"";
    "update:open-pr".exec = "nix run .#open-update-pr -- $XO_NIXPKG_UPDATE_PATHS";
    "update:queue-preflight".exec = "nix run .#queue-preflight";
    "update:rolling-failure".exec = "nix run .#rolling-failure";
    "update:queue".exec = "nix run .#queue-automation";
    "update:fix-hashes".exec = "nix run .#fix-nix-hashes";
  };

  enterTest = ''
    command -v nixfmt >/dev/null
    command -v node >/dev/null
    command -v yarn >/dev/null
    [[ $NIX_CONFIG == *https://xen-orchestra-ce.cachix.org* ]]
    [[ $NIX_CONFIG == *xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E=* ]]
  '';
}
