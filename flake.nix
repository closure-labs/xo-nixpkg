{
  description = "Xen Orchestra CE and libvhdi packages for NixOS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    libvhdi = {
      url = "git+https://codeberg.org/NiXOA/libvhdi.git?ref=refs/tags/latest";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      libvhdi,
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          xen-orchestra-ce = pkgs.callPackage ./default.nix { };
          libvhdi = libvhdi.packages.${system}.libvhdi;
          default = self.packages.${system}.xen-orchestra-ce;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            name = "xen-orchestra-ce-dev";
            packages = with pkgs; [
              curl
              gnused
              nix-prefetch-github
              nix-prefetch
              nixfmt
              nix-update
              git
              jq
            ];
            shellHook = ''
              echo "Xen Orchestra CE development shell"
              echo ""
              echo "Build packages:"
              echo "  nix build .#xen-orchestra-ce"
              echo "  nix build .#libvhdi"
              echo ""
              echo "Update xen-orchestra-ce:"
              echo "  ./scripts/update.sh"
              echo ""
              echo "Update libvhdi input:"
              echo "  nix flake lock --update-input libvhdi"
            '';
          };
        }
      );

      checks = forAllSystems (system: {
        xen-orchestra-ce = self.packages.${system}.xen-orchestra-ce;
        libvhdi = self.packages.${system}.libvhdi;
      });
    };
}
