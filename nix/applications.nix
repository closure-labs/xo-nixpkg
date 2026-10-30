{
  binaryCache,
  pkgs,
  nixpkgsPath,
  planRunner,
}:

let
  secretScanner = import ./secret-scanner.nix { inherit pkgs; };
  boundedGh = pkgs.writeShellApplication {
    name = "gh";
    runtimeInputs = [ pkgs.python3 ];
    text =
      builtins.replaceStrings
        [ "@GH@" "@PYTHON@" "@OPERATIONS@" ]
        [ "${pkgs.gh}/bin/gh" "${pkgs.python3}/bin/python3" "${../ci/decisions/operations.py}" ]
        (builtins.readFile ../ci/bounded-gh.sh);
  };

  mkRepositoryApplication =
    {
      name,
      script,
      runtimeInputs,
      prelude ? "",
    }:
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [
        pkgs.bash
      ]
      ++ map (package: if package == pkgs.gh then boundedGh else package) runtimeInputs;
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
    diffutils
    curl
    gawk
    git
    gnused
    jq
    nix
    python3
  ];
  cachePrelude = ''
    export XO_NIXPKG_CACHIX_CACHE_NAME=${pkgs.lib.escapeShellArg binaryCache.name}
    export XO_NIXPKG_CACHIX_CACHE_URL=${pkgs.lib.escapeShellArg binaryCache.url}
  '';
in
rec {
  ciAdmission = pkgs.writeShellApplication {
    name = "xo-nixpkg-ci-admission";
    runtimeInputs = [
      pkgs.python3
      boundedGh
    ];
    text = ''
      export PYTHONPATH=${../ci/decisions}
      exec python3 ${../ci/decisions/ci_admission.py} --policy ${../ci/ci-admission-policy.json}
    '';
  };
  cacheDoctor = pkgs.writeShellApplication {
    name = "xo-nixpkg-cache-doctor";
    runtimeInputs = [
      pkgs.python3
      pkgs.devenv
    ];
    text = ''
      export PYTHONPATH=${../ci/decisions}
      exec python3 ${../ci/cache-doctor.py} "$@"
    '';
  };

  securityApplicability =
    (pkgs.writeShellApplication {
      name = "xo-nixpkg-security-applicability";
      runtimeInputs = [ pkgs.python3 ];
      text = ''
        exec python3 ${./security-applicability.py} "$@"
      '';
    }).overrideAttrs
      (_: {
        passthru.source = ./security-applicability.py;
      });

  securityScan = mkRepositoryApplication {
    name = "xo-nixpkg-security-scan";
    script = ../ci/security-scan.sh;
    runtimeInputs =
      (with pkgs; [
        coreutils
        grype
        jq
        nix
        python3
      ])
      ++ [
        securityApplicability
        securityDatabase
      ];
    prelude = ''
      export XO_OPERATIONS_SOURCE=${../ci/decisions/operations.py}
      export XO_ADVISORY_UNION_SOURCE=${../ci/advisory-union.py}
      XO_SECURITY_NORMALIZE_SOURCE=${./security-normalize.py}
      XO_SECURITY_APPLICABILITY_RULES=${./security-applicability-rules.json}
      export XO_SECURITY_NORMALIZE_SOURCE XO_SECURITY_APPLICABILITY_RULES
    '';
  };

  securityReviewAll = mkRepositoryApplication {
    name = "xo-nixpkg-security-review-all";
    script = ../ci/security-review-all.sh;
    runtimeInputs = with pkgs; [
      python3
      gh
      oras
      git
      coreutils
      securityScan
      securityDatabase
    ];
    prelude = ''
      export PYTHONPATH=${decisions}/lib/decisions
      export XO_OPERATIONS_SOURCE=${../ci/decisions/operations.py}
      export XO_ADVISORY_INPUTS_SOURCE=${../ci/advisory-inputs.py}
      export XO_NIXPKG_RETAINED_FETCH_SOURCE=${../ci/fetch-retained.py}
    '';
  };

  auditPolicy = mkRepositoryApplication {
    name = "xo-nixpkg-audit-policy";
    script = ../ci/audit-policy.sh;
    runtimeInputs = with pkgs; [
      python3
      gh
    ];
    prelude = ''
      export XO_NIXPKG_POLICY_AUDIT_SOURCE=${../ci/audit-policy.py}
      export PYTHONPATH=${decisions}/lib/decisions
    '';
  };
  restoreProducts = mkRepositoryApplication {
    name = "xo-nixpkg-restore-products";
    script = ../ci/restore-products.sh;
    runtimeInputs = with pkgs; [
      python3
      nix
      publicationGate
    ];
    prelude = ''
      export XO_NIXPKG_RESTORER=${../ci/restore-products.py}
      export PYTHONPATH=${decisions}/lib/decisions
      export XO_NIXPKG_DISTRIBUTION_CACHE_SOURCE=${../ci/distribution-cache.py}
    '';
  };
  consumerProbe = mkRepositoryApplication {
    name = "xo-nixpkg-consumer-probe";
    script = ../ci/consumer-probe.sh;
    runtimeInputs = with pkgs; [
      python3
      nix
      gh
    ];
    prelude = ''
      export PYTHONPATH=${decisions}/lib/decisions
      export XO_NIXPKG_CONSUMER_PROBE_SOURCE=${../ci/consumer-probe.py}
    '';
  };
  repositoryAudit = mkRepositoryApplication {
    name = "xo-nixpkg-repository-audit";
    script = ../ci/repository-audit.sh;
    runtimeInputs = [ pkgs.nix ];
  };
  publicationController = mkRepositoryApplication {
    name = "xo-nixpkg-publication-controller";
    script = ../ci/publication-controller.sh;
    runtimeInputs = with pkgs; [
      curl
      python3
      gh
      git
      oras
      publicationGate
      publish
      tagXoRelease
      tagRelease
      publishRelease
    ];
    prelude = cachePrelude + ''
      export XO_NIXPKG_PUBLICATION_CONTROLLER=${../ci/publication-controller.py}
      export PYTHONPATH=${decisions}/lib/decisions
    '';
  };
  refreshProducts = mkRepositoryApplication {
    name = "xo-nixpkg-refresh-products";
    script = ../ci/refresh-products.sh;
    runtimeInputs = with pkgs; [
      python3
      git
      nix
      securityNativeScan
      securityDatabase
    ];
    prelude = ''
      export XO_NIXPKG_REFRESHER=${../ci/refresh-products.py}
      export PYTHONPATH=${decisions}/lib/decisions
      export XO_NIXPKG_DISTRIBUTION_CACHE_SOURCE=${../ci/distribution-cache.py}
    '';
  };
  decisionCollect = mkRepositoryApplication {
    name = "xo-nixpkg-decision-collect";
    script = ../ci/decision-collect.sh;
    runtimeInputs = [ ];
  };
  decisionAuthority = mkRepositoryApplication {
    name = "xo-nixpkg-authority-controller";
    script = ../ci/decision-authority.sh;
    runtimeInputs = with pkgs; [
      oras
      decisions
    ];
  };
  inspectQualification = mkRepositoryApplication {
    name = "xo-nixpkg-inspect-qualification";
    script = ../ci/inspect-qualification.sh;
    runtimeInputs = with pkgs; [
      python3
      gh
      oras
    ];
    prelude = ''
      export PYTHONPATH=${decisions}/lib/decisions
      export XO_NIXPKG_RETAINED_FETCH_SOURCE=${../ci/fetch-retained.py}
      export XO_NIXPKG_QUALIFICATION_INSPECTOR=${../ci/inspect-qualification.py}
    '';
  };
  reconcileRetained = mkRepositoryApplication {
    name = "xo-nixpkg-reconcile-retained";
    script = ../ci/reconcile-retained.sh;
    runtimeInputs = with pkgs; [
      coreutils
      gh
      jq
      oras
      python3
      decisions
      inspectQualification
    ];
    prelude = ''
      export XO_NIXPKG_OPERATIONS_SOURCE=${../ci/decisions/operations.py}
      export XO_NIXPKG_RETAINED_FETCH_SOURCE=${../ci/fetch-retained.py}
      export XO_NIXPKG_RESCAN_VERIFIER_SOURCE=${../ci/verify-rescan-evidence.py}
      export PYTHONPATH=${decisions}/lib/decisions
    '';
  };
  queuePreflight = mkRepositoryApplication {
    name = "xo-nixpkg-queue-preflight";
    script = ../ci/queue-preflight.sh;
    runtimeInputs = [ pkgs.gh ];
  };
  rollingFailure = mkRepositoryApplication {
    name = "xo-nixpkg-rolling-failure";
    script = ../ci/rolling-failure.sh;
    runtimeInputs = [ ];
  };
  fetchEvidence = mkRepositoryApplication {
    name = "xo-nixpkg-fetch-evidence";
    script = ../ci/fetch-evidence.sh;
    runtimeInputs = with pkgs; [
      coreutils
      gh
      oras
      python3
      jq
      publicationGate
    ];
    prelude = ''
      export XO_NIXPKG_OPERATIONS_SOURCE=${../ci/decisions/operations.py}
      export XO_NIXPKG_RETAINED_FETCH_SOURCE=${../ci/fetch-retained.py}
      export XO_NIXPKG_RESCAN_VERIFIER_SOURCE=${../ci/verify-rescan-evidence.py}
      export PYTHONPATH=${decisions}/lib/decisions
    '';
  };
  ciVerdict = mkRepositoryApplication {
    name = "xo-nixpkg-ci-verdict";
    script = ../ci/ci-verdict.sh;
    runtimeInputs = [ ];
  };
  securityLint = mkRepositoryApplication {
    name = "xo-nixpkg-security-lint";
    script = ../ci/security-lint.sh;
    prelude = ''
      export XO_NIXPKG_HISTORY_SCAN_SOURCE=${../ci/history-scan.py}
      export XO_NIXPKG_SECRET_SCANNER=${secretScanner.package}/bin/gitleaks
      export XO_NIXPKG_SECRET_SCANNER_IDENTITY=${secretScanner.identity}
      export PYTHONPATH=${decisions}/lib/decisions
    '';
    runtimeInputs = with pkgs; [
      actionlint
      zizmor
      secretScanner.package
      python3
      nix
      git
    ];
  };
  secretScanEvidence = mkRepositoryApplication {
    name = "xo-nixpkg-secret-scan-evidence";
    script = ../ci/secret-scan-evidence.sh;
    runtimeInputs = [ pkgs.python3 pkgs.git pkgs.nix secretScanner.package ];
    prelude = ''
      export XO_NIXPKG_HISTORY_SCAN_SOURCE=${../ci/history-scan.py}
      export XO_NIXPKG_SECRET_SCANNER=${secretScanner.package}/bin/gitleaks
      export XO_NIXPKG_SECRET_SCANNER_IDENTITY=${secretScanner.identity}
      export XO_NIXPKG_SCANNER_FIXTURE_SOURCE=${../ci/scanner-fixtures.py}
      export XO_NIXPKG_SCANNER_EVIDENCE_SOURCE=${../ci/secret-scan-evidence.py}
      export PYTHONPATH=${decisions}/lib/decisions
    '';
  };
  decisionReconcile = mkRepositoryApplication {
    name = "xo-nixpkg-decision-reconcile-candidate";
    script = ../ci/decision-reconcile.sh;
    runtimeInputs = with pkgs; [
      coreutils
      decisions
    ];
  };
  securityInventory = mkRepositoryApplication {
    name = "xo-nixpkg-security-inventory";
    script = ../ci/security-inventory.sh;
    runtimeInputs = with pkgs; [
      python3
      nix
    ];
    prelude = ''
      export XO_NIXPKG_SECURITY_INVENTORY=${../ci/security-inventory.py}
      export XO_FINGERPRINTS_CORE=${../ci/decisions}
    '';
  };
  securityDatabase = pkgs.writeShellApplication {
    name = "xo-nixpkg-security-database";
    runtimeInputs = with pkgs; [
      python3
      grype
    ];
    text = ''
      exec python3 ${../ci/security-database.py} "$@"
    '';
  };
  securityNativeScan = mkRepositoryApplication {
    name = "xo-nixpkg-security-native-scan";
    script = ../ci/security-native-scan.sh;
    runtimeInputs = with pkgs; [
      coreutils
      grype
      jq
      python3
      securityDatabase
    ];
    prelude = ''
      export XO_NIXPKG_SECURITY_NORMALIZER=${../ci/security-normalize.py}
      export XO_FINGERPRINTS_CORE=${../ci/decisions}
    '';
  };
  qualifyProducts = mkRepositoryApplication {
    name = "xo-nixpkg-qualify-products";
    script = ../ci/qualify-products.sh;
    runtimeInputs = with pkgs; [
      coreutils
      git
      nix
      python3
      securityInventory
      securityNativeScan
      securityDatabase
      buildReuse
    ];
    prelude = ''
      export XO_NIXPKG_QUALIFIER=${../ci/qualify-products.py}
      export PYTHONPATH=${decisions}/lib/decisions
      export XO_NIXPKG_DISTRIBUTION_CACHE_SOURCE=${../ci/distribution-cache.py}
    '';
  };
  publicationGate = mkRepositoryApplication {
    name = "xo-nixpkg-publication-gate";
    script = ../ci/publication-gate.sh;
    runtimeInputs = [
      decisions
      pkgs.git
      pkgs.gh
      pkgs.python3
    ];
    prelude = ''
      export XO_NIXPKG_AUDIT_FRESHNESS_SOURCE=${../ci/audit-freshness.py}
      export PYTHONPATH=${decisions}/lib/decisions
    '';
  };
  decisions = pkgs.stdenvNoCC.mkDerivation {
    pname = "xo-nixpkg-decisions";
    version = "1";
    src = ../ci/decisions;
    nativeBuildInputs = [ pkgs.makeWrapper ];
    dontBuild = true;
    installPhase = ''
      mkdir -p "$out/lib/decisions" "$out/bin"
      cp *.py "$out/lib/decisions/"
      for leaf in authority admission proposal readiness publication recovery handoff reconcile check; do
        makeWrapper ${pkgs.python3}/bin/python3 "$out/bin/xo-nixpkg-decision-$leaf" \
          --add-flags "$out/lib/decisions/$leaf.py" \
          --prefix PATH : ${
            pkgs.lib.makeBinPath [
              pkgs.gh
              pkgs.git
              pkgs.oras
            ]
          }
      done
    '';
  };
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

  trustedCandidateNix = pkgs.writeShellApplication {
    name = "xo-nixpkg-candidate-nix";
    runtimeInputs = [ pkgs.nix ];
    text = ''
      exec ${pkgs.lib.getExe pkgs.nix} "$@" --no-accept-flake-config \
        --option sandbox true --option builders "" --option pure-eval true \
        --option allow-unsafe-native-code-during-evaluation false
    '';
  };

  buildReuse = mkRepositoryApplication {
    name = "xo-nixpkg-build-reuse";
    script = ../ci/build-reuse.sh;
    runtimeInputs = with pkgs; [
      python3
      gh
      git
      nix
      planRunner
      trustedCandidateNix
      secretScanner.package
    ];
    prelude = ''
      export XO_NIXPKG_BUILD_REUSE_SOURCE=${../ci/build-reuse.py}
      export XO_NIXPKG_HISTORY_SCAN_SOURCE=${../ci/history-scan.py}
      export XO_NIXPKG_SECRET_SCANNER=${secretScanner.package}/bin/gitleaks
      export XO_NIXPKG_SECRET_SCANNER_IDENTITY=${secretScanner.identity}
      export XO_NIXPKG_TRUSTED_NIX=${pkgs.lib.getExe pkgs.nix}
      export XO_NIXPKG_PLAN_RUNNER=${pkgs.lib.getExe planRunner}
      export XO_NIXPKG_TRUSTED_PLAN_NIX=${pkgs.lib.getExe trustedCandidateNix}
      export XO_NIXPKG_TRUSTED_CACHE_POLICY=${
        pkgs.writeText "xo-nixpkg-trusted-cache.json" (
          builtins.toJSON {
            schema = 1;
            inherit (binaryCache) name url publicKey;
          }
        )
      }
      export PYTHONPATH=${decisions}/lib/decisions
      export XO_NIXPKG_DISTRIBUTION_CACHE_SOURCE=${../ci/distribution-cache.py}
      export XO_NIXPKG_CI_EVIDENCE="''${RUNNER_TEMP:-''${TMPDIR:-/tmp}}/xo-nixpkg-ci-evidence"
    '';
  };

  publish = mkRepositoryApplication {
    name = "xo-nixpkg-publish";
    script = ../ci/publish.sh;
    runtimeInputs =
      with pkgs;
      [
        python3
        curl
        cachix
        coreutils
        jq
        nix
      ]
      ++ [
        planRunner
        publicationGate
        restoreProducts
      ];
    prelude = cachePrelude + ''
      export PUBLICATION_DESTINATIONS_SOURCE=${../ci/decisions/destinations.py}
    '';
  };

  publishRelease = mkRepositoryApplication {
    name = "xo-nixpkg-publish-release";
    script = ../ci/publish-release.sh;
    runtimeInputs = with pkgs; [
      jq
      publicationGate
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
      jq
      publicationGate
      coreutils
      git
      gnugrep
    ];
  };

  tagXoRelease = mkRepositoryApplication {
    name = "xo-nixpkg-tag-xo-release";
    script = ../ci/tag-xo-release.sh;
    runtimeInputs = with pkgs; [
      publicationGate
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
      python3
    ];
    prelude = ''
      export XO_NIXPKG_REVIEW_PROTOCOL=${../ci/decisions/review_protocol.py}
    '';
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
      coreutils
      nix
    ];
  };

  trustedPrewarm = mkRepositoryApplication {
    name = "xo-nixpkg-trusted-prewarm";
    script = ../ci/prewarm-candidate.sh;
    runtimeInputs =
      with pkgs;
      [
        coreutils
        gh
        git
        jq
        nix
      ]
      ++ [ planRunner ];
  };

  prewarmRelease = pkgs.writeShellApplication {
    name = "xo-nixpkg-prewarm-release";
    text = ''
      exec ${pkgs.lib.getExe trustedPrewarm} release "$@"
    '';
  };

  prewarmRuntime = pkgs.writeShellApplication {
    name = "xo-nixpkg-prewarm-runtime";
    text = ''
      exec ${pkgs.lib.getExe trustedPrewarm} runtime "$@"
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

  updateDevenvModules = mkRepositoryApplication {
    name = "xo-nixpkg-update-devenv-modules";
    script = ../ci/update-devenv-modules.sh;
    runtimeInputs = with pkgs; [
      coreutils
      git
      jq
      nix
      python3
    ];
  };
}
