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
      url = "github:vatesfr/xen-orchestra/40dede9e11c90562df5cb46c6a83a9d91efedae1";
      flake = false;
    };
    xo-stable = {
      url = "github:vatesfr/xen-orchestra/1a795970f9c60396967d9510e3d2a29b56f2da1d";
      flake = false;
    };
    xo-rolling = {
      url = "github:vatesfr/xen-orchestra/7e022940c37f2ebb4577d148eb3039afc90379aa";
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
          rolling-candidate = rolling;
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
          yarn = pkgs.yarn.override { nodejs = pkgs.nodejs_22; };
        in
        {
          default = pkgs.mkShellNoCC {
            packages = [
              pkgs.actionlint
              pkgs.cachix
              pkgs.curl
              pkgs.deadnix
              pkgs.git
              pkgs.gnused
              pkgs.jq
              pkgs.nixd
              pkgs.nixfmt
              pkgs.node-gyp
              pkgs.nodejs_22
              pkgs.pkg-config
              pkgs.python3
              pkgs.shellcheck
              pkgs.statix
              pkgs.valkey
              pkgs.zizmor
              yarn
            ];

            HUSKY = "0";
            DO_NOT_TRACK = "1";
            SCARF_ANALYTICS = "false";
            TURBO_TELEMETRY_DISABLED = "1";
            YARN_PRODUCTION = "false";
            NPM_CONFIG_PRODUCTION = "false";
            npm_config_node_gyp = "${pkgs.node-gyp}/bin/node-gyp";
            npm_config_python = "${pkgs.python3}/bin/python3";
          };

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
          classify-ci = mkApp applications.classifyCi "Classify a CI event into exact validation and publication plans";
          ci = mkApp applications.ci "Run the complete repository validation pipeline";
          run-ci-plan =
            mkApp self.packages.${system}.flake-plan-runner
              "Validate and execute a schema-v2 pure flake CI plan";
          publish = mkApp applications.publish "Publish final package closures to Cachix";
          publish-release = mkApp applications.publishRelease "Publish the immutable project tag as a GitHub release";
          tag-release = mkApp applications.tagRelease "Tag a successfully gated main release";
          trusted-update = mkApp applications.trustedUpdate "Validate and merge one trusted update";
          queue-automation = mkApp applications.queueAutomation "Queue trusted automation updates";
          update-xo-release = mkApp applications.updateXoRelease "Refresh the latest and stable XO release channels";
          update-xo-rolling = mkApp applications.updateXoRolling "Refresh the rolling XO channel from upstream HEAD";
          prewarm-rolling-candidate = mkApp applications.prewarmRolling "Realize and publish the exact rolling candidate closure";
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
