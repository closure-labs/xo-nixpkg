{
  description = "Xen Orchestra CE and libvhdi packages for NixOS";

  nixConfig = {
    extra-substituters = [ "https://xen-orchestra-ce.cachix.org" ];
    extra-trusted-public-keys = [
      "xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
      ...
    }:
    let
      supportedSystems = [
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      ciLib = import ./nix/ci-plan.nix { lib = nixpkgs.lib; };
      sourcePins = import ./nix/source-pins.nix { lib = nixpkgs.lib; };
      repositoryCheckNames = [
        "repository-policy"
        "source-update-fixtures"
        "automation-fixtures"
        "attribute-validator-fixtures"
      ];
    in
    {
      lib = ciLib // {
        projectVersion = nixpkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);
        inherit sourcePins;
        ciPlans = forAllSystems (system: {
          validation = ciLib.mkFlakeAttributePlan {
            name = "xo-nixpkg-validation";
            targets = [
              "checks.${system}.xen-orchestra-ce"
              "checks.${system}.xo-fuse-linkage"
              "checks.${system}.xo-server-service"
              "checks.${system}.libvhdi"
            ]
            ++ map (name: "checks.${system}.${name}") repositoryCheckNames;
          };
        });
      };

      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          xen-orchestra-ce = pkgs.callPackage ./default.nix {
            sourcePin = sourcePins.xenOrchestra;
          };
          libvhdi = pkgs.callPackage ./nix/libvhdi.nix {
            inherit (sourcePins.libvhdi) version;
            source = pkgs.fetchzip {
              inherit (sourcePins.libvhdi) url hash;
              extension = "tar";
            };
          };
          flake-attribute-validator = pkgs.callPackage ./nix/flake-attribute-validator.nix { };
          default = self.packages.${system}.xen-orchestra-ce;
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
            inherit pkgs;
            nixpkgsPath = nixpkgs.outPath;
            attributeValidator = self.packages.${system}.flake-attribute-validator;
          };
          mkApp = package: description: {
            type = "app";
            program = nixpkgs.lib.getExe package;
            meta.description = description;
          };
        in
        {
          ci = mkApp applications.ci "Run the complete repository validation pipeline";
          validate-ci-plan =
            mkApp self.packages.${system}.flake-attribute-validator
              "Validate and build a pure flake attribute plan";
          publish = mkApp applications.publish "Publish final package closures to Cachix";
          tag-release = mkApp applications.tagRelease "Tag a successfully gated main release";
          trusted-update = mkApp applications.trustedUpdate "Validate and merge one trusted update";
          queue-automation = mkApp applications.queueAutomation "Queue trusted automation updates";
          update-xo-release = mkApp applications.updateXoRelease "Update and validate the latest XO release";
          update-xo-upstream = mkApp applications.updateXoUpstream "Update and validate XO upstream HEAD";
          update-libvhdi = mkApp applications.updateLibvhdi "Update and validate the official libvhdi release";
          maintain-latest-upstream = mkApp applications.maintainLatestUpstream "Maintain the latest-upstream tag";
          forgejo-update = mkApp applications.forgejoUpdate "Create a validated Forgejo update pull request";
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          repositoryChecks = import ./nix/repository-checks.nix {
            inherit pkgs self;
          };
        in
        repositoryChecks
        // {
          xen-orchestra-ce = self.packages.${system}.xen-orchestra-ce;
          xo-fuse-linkage = self.packages.${system}.xen-orchestra-ce;
          xo-server-service = import ./nix/tests/xo-server-service.nix {
            inherit pkgs;
            xen-orchestra-ce = self.packages.${system}.xen-orchestra-ce;
          };
          libvhdi = self.packages.${system}.libvhdi;
        }
      );
    };
}
