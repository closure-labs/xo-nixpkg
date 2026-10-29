rec {
  description = "Xen Orchestra CE and libvhdi packages for NixOS";

  nixConfig = {
    # Flake configuration is security-sensitive and Nix requires these values
    # to be literal (imported or interpolated values are rejected as thunks).
    extra-substituters = [ "https://xen-orchestra-ce.cachix.org" ];
    extra-trusted-public-keys = [
      "xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    xo-latest = {
      url = "github:vatesfr/xen-orchestra/5999d53e0b6172820567a1caee67da798e5a673f";
      flake = false;
    };
    xo-stable = {
      url = "github:vatesfr/xen-orchestra/a2bd181d3528a61a45bbd4fe99686875fe8eebf8";
      flake = false;
    };
    xo-rolling = {
      url = "github:vatesfr/xen-orchestra/a50776cb7d013b359a34d9b0103665d158db1f0a";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      xo-latest,
      xo-rolling,
      xo-stable,
      ...
    }:
    let
      supportedSystems = [
        "x86_64-linux"
      ];
      binaryCache = {
        name = "xen-orchestra-ce";
        url = builtins.head nixConfig.extra-substituters;
        publicKey = builtins.head nixConfig.extra-trusted-public-keys;
      };
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      ciLib = import ./nix/ci-plan.nix { lib = nixpkgs.lib; };
      classifierContract = builtins.fromJSON (builtins.readFile ./ci/classifier.json);
      sourcePins = import ./nix/source-pins.nix { lib = nixpkgs.lib; };
    in
    {
      lib = ciLib // {
        projectVersion = nixpkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);
        inherit binaryCache sourcePins;
        ciClassifier = classifierContract;
        ciSecurityFixtures = forAllSystems (
          system:
          import ./nix/security-fixtures.nix {
            pkgs = nixpkgs.legacyPackages.${system};
            source = self;
          }
        );
        ciPlans = forAllSystems (system: {
          validation = ciLib.mkCiPlan {
            name = "xo-nixpkg-validation";
            targets = map (target: {
              inherit (target) name;
              attribute = builtins.replaceStrings [ "x86_64-linux" ] [ system ] target.attribute;
            }) classifierContract.validationTargets;
          };
          publish = ciLib.mkCiPlan {
            name = "xo-nixpkg-publish";
            targets = map (target: {
              inherit (target) name;
              attribute = builtins.replaceStrings [ "x86_64-linux" ] [ system ] target.attribute;
            }) classifierContract.publicationTargets;
          };
        });
      };

      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          mkXo =
            channel: source:
            let
              pin = sourcePins.xenOrchestra.channels.${channel};
            in
            pkgs.callPackage ./default.nix {
              inherit channel source;
              inherit (pin) docsYarnHash version yarnHash;
              sourceRev = pin.rev;
            };
          latest = mkXo "latest" xo-latest;
          stable = mkXo "stable" xo-stable;
          rolling = mkXo "rolling" xo-rolling;
          mkSupplyProtector =
            channel: package: source:
            pkgs.callPackage ./nix/supply-protector.nix {
              cachePublicKey = binaryCache.publicKey;
              cacheUrl = binaryCache.url;
              inherit channel package;
              inherit (sourcePins.xenOrchestra.channels.${channel}) version;
              sourceRev = source.rev;
              sourceTimestamp = source.lastModified;
            };
          latestSupplyProtector = mkSupplyProtector "latest" latest xo-latest;
          stableSupplyProtector = mkSupplyProtector "stable" stable xo-stable;
          rollingSupplyProtector = mkSupplyProtector "rolling" rolling xo-rolling;
          flakePlanRunner = pkgs.callPackage ./nix/flake-plan-runner.nix { };
          applications = import ./nix/applications.nix {
            inherit binaryCache pkgs;
            nixpkgsPath = nixpkgs.outPath;
            planRunner = flakePlanRunner;
          };
          automationRuntime = pkgs.symlinkJoin {
            name = "xo-nixpkg-automation-runtime-${self.lib.projectVersion}";
            paths = [ flakePlanRunner ] ++ builtins.attrValues applications;
            meta.description = "Packaged xo-nixpkg CI, publication, queue, and updater applications";
          };
        in
        {
          inherit latest rolling stable;
          devenv = pkgs.devenv;
          rolling-candidate = rolling;
          runtime-node = (pkgs.callPackage ./nix/runtime-node.nix { }).nodejs;
          supply-protector = latestSupplyProtector;
          supply-protector-latest = latestSupplyProtector;
          supply-protector-stable = stableSupplyProtector;
          supply-protector-rolling = rollingSupplyProtector;
          latest-upstream = rolling;
          xen-orchestra-ce = latest;
          xen-orchestra-ce-latest = latest;
          xen-orchestra-ce-stable = stable;
          xen-orchestra-ce-rolling = rolling;
          xen-orchestra-ce-latest-upstream = rolling;
          automation-runtime = automationRuntime;
          security-applicability = applications.securityApplicability;
          security-scan = applications.securityScan;
          security-review-all = applications.securityReviewAll;
          libvhdi = pkgs.callPackage ./nix/libvhdi.nix {
            inherit (sourcePins.libvhdi) version;
            source = pkgs.fetchzip {
              inherit (sourcePins.libvhdi) url hash;
              extension = "tar";
            };
          };
          flake-plan-runner = flakePlanRunner;
          default = latest;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          developmentEnvironment = import ./nix/development-environment.nix { inherit pkgs; };
        in
        {
          default = pkgs.mkShellNoCC (
            developmentEnvironment.env
            // {
              packages = developmentEnvironment.packages ++ [ pkgs.devenv ];
            }
          );

          updater = pkgs.mkShellNoCC {
            packages = [
              pkgs.coreutils
              pkgs.curl
              pkgs.git
              pkgs.gnused
              pkgs.jq
              pkgs.nix
              pkgs.nix-prefetch
              pkgs.nix-update
            ];

            XO_NIXPKG_NIXPKGS_PATH = nixpkgs.outPath;
            XO_NIXPKG_UPDATE_IN_DEV_SHELL = "1";
          };
        }
      );

      apps = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          applications = import ./nix/applications.nix {
            inherit binaryCache pkgs;
            nixpkgsPath = nixpkgs.outPath;
            planRunner = self.packages.${system}.flake-plan-runner;
          };
          mkApp = package: description: {
            type = "app";
            program = nixpkgs.lib.getExe package;
            meta.description = description;
          };
        in
        {
          cache-doctor = mkApp applications.cacheDoctor "Check named Cachix token permissions without publishing";
          audit-policy = mkApp applications.auditPolicy "Audit effective protection with read-only administration credentials";
          consumer-probe = mkApp applications.consumerProbe "Verify downloaded public product bytes and signatures in a clean store";
          repository-audit = mkApp applications.repositoryAudit "Run the complete repository contract";
          publication-controller = mkApp applications.publicationController "Publish exact admitted products with durable recovery checkpoints";
          refresh-products = mkApp applications.refreshProducts "Rescan exact retained products without changing approval identity";
          decision-collect = mkApp applications.decisionCollect "Collect decision event metadata";
          ci-admission = mkApp applications.ciAdmission "Approve CI runs for trusted PR authors";
          decision-authority = mkApp applications.decisionAuthority "Publish the App-origin human authority check";
          inspect-qualification = mkApp applications.inspectQualification "Inspect exact producer observations without downloading closure payloads";
          reconcile-retained = mkApp applications.reconcileRetained "Reconcile retained security and release approvals";
          queue-preflight = mkApp applications.queuePreflight "Check merge queue runtime credential";
          rolling-failure = mkApp applications.rollingFailure "Report a preserved failed rolling candidate";
          fetch-evidence = mkApp applications.fetchEvidence "Fetch an authenticated immutable qualification packet";
          security-lint = mkApp applications.securityLint "Validate workflow security and evidence contracts";
          qualify-products = mkApp applications.qualifyProducts "Build complete four-profile runtime security evidence";
          build-reuse = mkApp applications.buildReuse "Build sandboxed candidates and restore authenticated exact CI outputs";
          security-database = mkApp applications.securityDatabase "Prepare one verified run-local vulnerability database";
          ci-verdict = mkApp applications.ciVerdict "Enforce the classified validation result";
          decision-reconcile = mkApp applications.decisionReconcile "Reconcile authenticated security or release proposals";
          decision-readiness = mkApp (pkgs.writeShellScriptBin "xo-nixpkg-readiness" ''
            exec ${applications.decisions}/bin/xo-nixpkg-decision-readiness --config ci/decision-policy.json "$@"
          '') "Audit live publication authority and policy";
          classify-ci = mkApp applications.classifyCi "Classify a CI event into exact validation and publication plans";
          ci = mkApp applications.ci "Run the complete repository validation pipeline";
          security-applicability = mkApp applications.securityApplicability "Revalidate exact source-bound security applicability evidence";
          security-review-all = mkApp applications.securityReviewAll "Review all advisory channels with one verified fresh database";
          security-scan = mkApp applications.securityScan "Scan one XO channel and report unresolved critical findings";
          run-ci-plan =
            mkApp self.packages.${system}.flake-plan-runner
              "Validate and execute a schema-v2 pure flake CI plan";
          publish = mkApp applications.publish "Publish final package closures to Cachix";
          fix-nix-hashes = mkApp applications.fixNixHashes "Repair stale Nix hashes on a trusted Dependabot pull request";
          publish-release = mkApp applications.publishRelease "Publish the immutable project tag as a GitHub release";
          tag-release = mkApp applications.tagRelease "Tag a successfully gated main release";
          tag-xo-release = mkApp applications.tagXoRelease "Tag a newly gated Xen Orchestra latest package release";
          trusted-update = mkApp applications.trustedUpdate "Validate and merge one trusted update";
          queue-automation = mkApp applications.queueAutomation "Queue trusted automation updates";
          update-xo-release = mkApp applications.updateXoRelease "Refresh the latest and stable XO release channels";
          update-xo-rolling = mkApp applications.updateXoRolling "Refresh the rolling XO channel from upstream HEAD";
          prewarm-rolling-candidate = mkApp applications.prewarmRolling "Realize the exact rolling candidate locally";
          prewarm-release-candidate = mkApp applications.prewarmRelease "Realize exact official channel candidates locally";
          prewarm-runtime = mkApp applications.prewarmRuntime "Realize the protected source runtime locally";
          update-xo-upstream = mkApp applications.updateXoRolling "Compatibility alias for the rolling XO updater";
          update-libvhdi = mkApp applications.updateLibvhdi "Update and validate the official libvhdi release";
          open-update-pr = mkApp applications.openUpdatePr "Commit and open one allowlisted source update pull request";
          update-flake-lock = mkApp applications.updateFlakeLock "Refresh and validate the Nixpkgs lock";
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          applications = import ./nix/applications.nix {
            inherit binaryCache pkgs;
            nixpkgsPath = nixpkgs.outPath;
            planRunner = self.packages.${system}.flake-plan-runner;
          };
          repositoryChecks = import ./nix/repository-checks.nix {
            securityFixtures = self.lib.ciSecurityFixtures.${system};
            inherit
              applications
              pkgs
              self
              ;
          };
        in
        repositoryChecks
        // {
          xo-latest = self.packages.${system}.latest;
          xo-stable = self.packages.${system}.stable;
          xo-rolling = self.packages.${system}.rolling;
          supply-protector-latest = self.packages.${system}.supply-protector-latest;
          supply-protector-stable = self.packages.${system}.supply-protector-stable;
          supply-protector-rolling = self.packages.${system}.supply-protector-rolling;
          xen-orchestra-ce = self.packages.${system}.latest;
          xo-fuse-linkage = self.packages.${system}.latest;
          xo-server-service = import ./nix/tests/xo-server-service.nix {
            inherit pkgs;
            xen-orchestra-ce = self.packages.${system}.latest;
          };
          libvhdi = self.packages.${system}.libvhdi;
        }
      );
    };
}
