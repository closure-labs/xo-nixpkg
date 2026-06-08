{
  description = "Xen Orchestra CE and libvhdi packages for NixOS";

  nixConfig = {
    extra-substituters = [
      "https://devenv.cachix.org"
      "https://libvhdi-nixpkg.cachix.org"
    ];
    extra-trusted-public-keys = [
      "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw="
      "libvhdi-nixpkg.cachix.org-1:HvYHKZcfczn2nGfCmd7F21E/MDZrlaXtN3p9mWAZT/4="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    devenv.url = "github:cachix/devenv";
    libvhdi = {
      url = "git+https://github.com/declarative-dale/libvhdi-nixpkg.git?ref=refs/tags/20251119";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      devenv,
      libvhdi,
      ...
    }@inputs:
    let
      supportedSystems = [
        "x86_64-linux"
      ];
      devShellSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      forAllDevShellSystems = nixpkgs.lib.genAttrs devShellSystems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          xen-orchestra-ce = pkgs.callPackage ./default.nix { };
          libvhdi = libvhdi.packages.${system}.libvhdi-fuse2;
          libvhdi-fuse2 = libvhdi.packages.${system}.libvhdi-fuse2;
          libvhdi-fuse3 = libvhdi.packages.${system}.libvhdi-fuse3;
          default = self.packages.${system}.xen-orchestra-ce;
        }
      );

      devShells = forAllDevShellSystems (system: {
        default = devenv.lib.mkShell {
          inherit inputs;
          pkgs = nixpkgs.legacyPackages.${system};
          modules = [ ./devenv.nix ];
        };
      });

      checks = forAllSystems (system: {
        xen-orchestra-ce = self.packages.${system}.xen-orchestra-ce;
        libvhdi = self.packages.${system}.libvhdi;
        libvhdi-fuse2 = self.packages.${system}.libvhdi-fuse2;
        libvhdi-fuse3 = self.packages.${system}.libvhdi-fuse3;
      });
    };
}
