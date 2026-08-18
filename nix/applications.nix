{
  pkgs,
  nixpkgsPath,
  planRunner,
}:

let
  mkRepositoryApplication =
    {
      name,
      script,
      runtimeInputs,
      arguments ? [ ],
      environment ? "",
    }:
    pkgs.writeShellApplication {
      inherit name runtimeInputs;
      text = ''
        repo_root="''${XO_NIXPKG_SOURCE_ROOT:-$PWD}"
        if [[ ! -f "$repo_root/flake.nix" ]]; then
          echo "Run this command from the xo-nixpkg repository root or set XO_NIXPKG_SOURCE_ROOT" >&2
          exit 2
        fi
        export XO_NIXPKG_SOURCE_ROOT="$repo_root"
        cd "$repo_root"
        ${environment}
        exec ${pkgs.bash}/bin/bash "$repo_root/${script}" ${pkgs.lib.escapeShellArgs arguments} "$@"
      '';
    };

  updateRuntimeInputs = with pkgs; [
    coreutils
    curl
    gawk
    git
    gnused
    jq
    nix
  ];
in
rec {
  ci = mkRepositoryApplication {
    name = "xo-nixpkg-ci";
    script = "ci/run.sh";
    runtimeInputs =
      with pkgs;
      [
        coreutils
        git
        nix
      ]
      ++ [ planRunner ];
    environment = ''
      export XO_NIXPKG_CI_PLAN=lib.ciPlans.${pkgs.stdenv.hostPlatform.system}.validation
    '';
  };

  publish = mkRepositoryApplication {
    name = "xo-nixpkg-publish";
    script = "ci/publish.sh";
    runtimeInputs =
      with pkgs;
      [
        cachix
        coreutils
        jq
        nix
      ]
      ++ [ planRunner ];
    environment = ''
      export XO_NIXPKG_PUBLISH_PLAN=lib.ciPlans.${pkgs.stdenv.hostPlatform.system}.publish
    '';
  };

  publishRelease = mkRepositoryApplication {
    name = "xo-nixpkg-publish-release";
    script = "ci/publish-release.sh";
    runtimeInputs = with pkgs; [
      coreutils
      gawk
      gh
      git
    ];
  };

  tagRelease = mkRepositoryApplication {
    name = "xo-nixpkg-tag-release";
    script = "ci/tag-release.sh";
    runtimeInputs = with pkgs; [
      coreutils
      git
      gnugrep
    ];
  };

  trustedUpdate = mkRepositoryApplication {
    name = "xo-nixpkg-trusted-update";
    script = "ci/trusted-update.sh";
    runtimeInputs = with pkgs; [
      coreutils
      gh
      jq
    ];
  };

  queueAutomation = mkRepositoryApplication {
    name = "xo-nixpkg-queue-automation";
    script = "ci/queue-automation.sh";
    runtimeInputs = with pkgs; [
      coreutils
      gh
      jq
    ];
  };

  updateXoRelease = mkRepositoryApplication {
    name = "xo-nixpkg-update-xo-release";
    script = "ci/update-xo.sh";
    arguments = [ "--release" ];
    runtimeInputs = updateRuntimeInputs;
    environment = ''
      export XO_NIXPKG_NIXPKGS_PATH=${pkgs.lib.escapeShellArg nixpkgsPath}
      export XO_NIXPKG_UPDATE_IN_DEV_SHELL=1
    '';
  };

  updateXoUpstream = mkRepositoryApplication {
    name = "xo-nixpkg-update-xo-upstream";
    script = "ci/update-xo.sh";
    arguments = [ "--upstream" ];
    runtimeInputs = updateRuntimeInputs;
    environment = ''
      export XO_NIXPKG_NIXPKGS_PATH=${pkgs.lib.escapeShellArg nixpkgsPath}
      export XO_NIXPKG_UPDATE_IN_DEV_SHELL=1
    '';
  };

  updateLibvhdi = mkRepositoryApplication {
    name = "xo-nixpkg-update-libvhdi";
    script = "ci/update-libvhdi.sh";
    runtimeInputs = with pkgs; [
      coreutils
      curl
      jq
      nix
    ];
  };

  maintainLatestUpstream = mkRepositoryApplication {
    name = "xo-nixpkg-maintain-latest-upstream";
    script = "ci/maintain-latest-upstream.sh";
    runtimeInputs = updateRuntimeInputs;
    environment = ''
      export XO_NIXPKG_NIXPKGS_PATH=${pkgs.lib.escapeShellArg nixpkgsPath}
      export XO_NIXPKG_UPDATE_IN_DEV_SHELL=1
    '';
  };

  forgejoUpdate = mkRepositoryApplication {
    name = "xo-nixpkg-forgejo-update";
    script = "ci/forgejo-update.sh";
    runtimeInputs = updateRuntimeInputs;
    environment = ''
      export XO_NIXPKG_NIXPKGS_PATH=${pkgs.lib.escapeShellArg nixpkgsPath}
      export XO_NIXPKG_UPDATE_IN_DEV_SHELL=1
    '';
  };

  openUpdatePr = mkRepositoryApplication {
    name = "xo-nixpkg-open-update-pr";
    script = "ci/open-update-pr.sh";
    runtimeInputs = with pkgs; [
      coreutils
      gh
      git
    ];
  };

  updateFlakeLock = mkRepositoryApplication {
    name = "xo-nixpkg-update-flake-lock";
    script = "ci/update-flake-lock.sh";
    runtimeInputs = with pkgs; [
      coreutils
      git
      nix
    ];
  };
}
