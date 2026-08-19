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
in
rec {
  classifyCi = mkRepositoryApplication {
    name = "xo-nixpkg-classify-ci";
    script = ../ci/classify.sh;
    runtimeInputs = with pkgs; [
      coreutils
      gh
      git
      jq
    ];
  };

  prepareCi = pkgs.writeShellApplication {
    name = "xo-nixpkg-prepare-ci";
    runtimeInputs = with pkgs; [ nix ];
    text = ''
      if (( $# > 1 )); then
        echo 'usage: xo-nixpkg-prepare-ci [GITHUB_OUTPUT]' >&2
        exit 2
      fi

      runtime_nix="''${XO_NIXPKG_RUNTIME_NIX:-nix}"
      prepared=$("$runtime_nix" eval --impure --json --file ${./prepare-ci-runtime.nix})
      if (( $# == 1 )); then
        printf 'workflow=%s\n' "$prepared" >>"$1"
      else
        printf '%s\n' "$prepared"
      fi
    '';
  };

  ciGate = pkgs.writeShellApplication {
    name = "xo-nixpkg-ci-gate";
    runtimeInputs = with pkgs; [ nix ];
    text = ''
      if (( $# != 0 )); then
        echo 'usage: xo-nixpkg-ci-gate' >&2
        exit 2
      fi

      runtime_nix="''${XO_NIXPKG_RUNTIME_NIX:-nix}"
      exec "$runtime_nix" eval --impure --raw --file ${./ci-gate-runtime.nix}
    '';
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

  tagRelease = mkRepositoryApplication {
    name = "xo-nixpkg-tag-release";
    script = ../ci/tag-release.sh;
    runtimeInputs = with pkgs; [
      coreutils
      git
      gnugrep
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

  updateXoSource = mkRepositoryApplication {
    name = "xo-nixpkg-update-xo-source";
    script = ../scripts/update.sh;
    runtimeInputs = updateRuntimeInputs;
  };

  updateXo = mkRepositoryApplication {
    name = "xo-nixpkg-update-xo";
    script = ../ci/update-xo.sh;
    runtimeInputs = updateRuntimeInputs ++ [ updateXoSource ];
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

  updateXoUpstream = pkgs.writeShellApplication {
    name = "xo-nixpkg-update-xo-upstream";
    text = ''
      exec ${pkgs.lib.getExe updateXo} --upstream "$@"
    '';
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

  maintainLatestUpstream = mkRepositoryApplication {
    name = "xo-nixpkg-maintain-latest-upstream";
    script = ../ci/maintain-latest-upstream.sh;
    runtimeInputs = updateRuntimeInputs ++ [ updateXoUpstream ];
  };

  forgejoUpdate = mkRepositoryApplication {
    name = "xo-nixpkg-forgejo-update";
    script = ../ci/forgejo-update.sh;
    runtimeInputs = updateRuntimeInputs ++ [
      updateLibvhdi
      updateXoRelease
    ];
  };

  openUpdatePr = mkRepositoryApplication {
    name = "xo-nixpkg-open-update-pr";
    script = ../ci/open-update-pr.sh;
    runtimeInputs = with pkgs; [
      coreutils
      gh
      git
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
