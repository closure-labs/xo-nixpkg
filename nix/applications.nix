{
  binaryCache,
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
      prelude ? "",
    }:
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [ pkgs.bash ] ++ runtimeInputs;
      text = ''
        repo_root="''${XO_NIXPKG_SOURCE_ROOT:-$PWD}"
        if [[ ! -f "$repo_root/flake.nix" ]]; then
          echo "Run this command from the xo-nixpkg repository root or set XO_NIXPKG_SOURCE_ROOT" >&2
          exit 2
        fi
        export XO_NIXPKG_SOURCE_ROOT="$repo_root"
        cd "$repo_root"
        ${prelude}
        ${builtins.readFile script}
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
  cachePrelude = ''
    export XO_NIXPKG_CACHIX_CACHE_NAME=${pkgs.lib.escapeShellArg binaryCache.name}
  '';
in
rec {
  classifyCi = mkRepositoryApplication {
    name = "xo-nixpkg-classify-ci";
    script = ../ci/classify.sh;
    runtimeInputs = with pkgs; [
      coreutils
      gawk
      gh
      git
      gnugrep
      gnused
      jq
    ];
  };

  ci = mkRepositoryApplication {
    name = "xo-nixpkg-ci";
    script = ../ci/run.sh;
    runtimeInputs =
      with pkgs;
      [
        coreutils
        git
        jq
        nix
      ]
      ++ [
        classifyCi
        planRunner
      ];
  };

  publish = mkRepositoryApplication {
    name = "xo-nixpkg-publish";
    script = ../ci/publish.sh;
    runtimeInputs =
      with pkgs;
      [
        cachix
        coreutils
        jq
        nix
      ]
      ++ [ planRunner ];
    prelude = cachePrelude;
  };

  publishRelease = mkRepositoryApplication {
    name = "xo-nixpkg-publish-release";
    script = ../ci/publish-release.sh;
    runtimeInputs = with pkgs; [
      coreutils
      gawk
      gh
      git
    ];
  };

  fixNixHashes = mkRepositoryApplication {
    name = "xo-nixpkg-fix-nix-hashes";
    script = ../ci/fix-nix-hashes.sh;
    runtimeInputs = with pkgs; [
      coreutils
      gh
      git
    ];
  };

  tagRelease = mkRepositoryApplication {
    name = "xo-nixpkg-tag-release";
    script = ../ci/tag-release.sh;
    runtimeInputs = with pkgs; [
      coreutils
      git
      gnugrep
    ];
  };

  tagXoRelease = mkRepositoryApplication {
    name = "xo-nixpkg-tag-xo-release";
    script = ../ci/tag-xo-release.sh;
    runtimeInputs = with pkgs; [
      coreutils
      git
      jq
    ];
  };

  trustedUpdate = mkRepositoryApplication {
    name = "xo-nixpkg-trusted-update";
    script = ../ci/trusted-update.sh;
    runtimeInputs = with pkgs; [
      coreutils
      gh
      jq
    ];
  };

  queueAutomation = mkRepositoryApplication {
    name = "xo-nixpkg-queue-automation";
    script = ../ci/queue-automation.sh;
    runtimeInputs =
      with pkgs;
      [
        coreutils
        gh
        jq
      ]
      ++ [ trustedUpdate ];
  };

  updateXo = mkRepositoryApplication {
    name = "xo-nixpkg-update-xo";
    script = ../ci/update-xo.sh;
    runtimeInputs = updateRuntimeInputs;
    prelude = ''
      export XO_NIXPKG_NIXPKGS_PATH="''${XO_NIXPKG_NIXPKGS_PATH:-${nixpkgsPath}}"
      export XO_NIXPKG_UPDATE_IN_DEV_SHELL=1
    '';
  };

  updateXoRelease = pkgs.writeShellApplication {
    name = "xo-nixpkg-update-xo-release";
    text = ''
      exec ${pkgs.lib.getExe updateXo} --release "$@"
    '';
  };

  updateXoRolling = pkgs.writeShellApplication {
    name = "xo-nixpkg-update-xo-rolling";
    text = ''
      exec ${pkgs.lib.getExe updateXo} --rolling "$@"
    '';
  };

  prewarmRolling = mkRepositoryApplication {
    name = "xo-nixpkg-prewarm-rolling";
    script = ../ci/prewarm-rolling.sh;
    runtimeInputs = with pkgs; [
      cachix
      coreutils
      nix
    ];
    prelude = cachePrelude;
  };

  updateLibvhdiSource = mkRepositoryApplication {
    name = "xo-nixpkg-update-libvhdi-source";
    script = ../scripts/update-libvhdi.sh;
    runtimeInputs = with pkgs; [
      coreutils
      curl
      jq
      nix
    ];
  };

  updateLibvhdi = mkRepositoryApplication {
    name = "xo-nixpkg-update-libvhdi";
    script = ../ci/update-libvhdi.sh;
    runtimeInputs =
      with pkgs;
      [
        coreutils
        curl
        jq
        nix
      ]
      ++ [ updateLibvhdiSource ];
  };

  openUpdatePr = mkRepositoryApplication {
    name = "xo-nixpkg-open-update-pr";
    script = ../ci/open-update-pr.sh;
    runtimeInputs = with pkgs; [
      coreutils
      gh
      git
      jq
    ];
  };

  updateFlakeLock = mkRepositoryApplication {
    name = "xo-nixpkg-update-flake-lock";
    script = ../ci/update-flake-lock.sh;
    runtimeInputs = with pkgs; [
      coreutils
      git
      nix
    ];
  };
}
