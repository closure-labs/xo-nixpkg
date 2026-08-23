# SPDX-License-Identifier: Apache-2.0
# Example: Using xen-orchestra-ce-nix packages in a NixOS configuration

{
  description = "Example NixOS configuration using xen-orchestra-ce-nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    xo-ce-nix.url = "git+ssh://git@github.com/closure-labs/xo-nixpkg.git";
  };

  outputs =
    {
      self,
      nixpkgs,
      xo-ce-nix,
    }:
    {
      nixosConfigurations.example = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          (
            { config, pkgs, ... }:
            {
              # Install packages
              environment.systemPackages = [
                xo-ce-nix.packages.x86_64-linux.xen-orchestra-ce
                xo-ce-nix.packages.x86_64-linux.libvhdi
              ];

              # Example: Basic xo-server systemd service
              # Note: This is a minimal example. For an appliance, see Maestro.
              systemd.services.xo-server = {
                description = "Xen Orchestra Server";
                wantedBy = [ "multi-user.target" ];
                after = [
                  "network.target"
                  "redis.service"
                ];
                requires = [ "redis.service" ];

                serviceConfig = {
                  Type = "simple";
                  ExecStart = "${xo-ce-nix.packages.x86_64-linux.xen-orchestra-ce}/bin/xo-server";
                  Restart = "on-failure";
                  User = "xo";
                  Group = "xo";
                  WorkingDirectory = "/var/lib/xo";
                  StateDirectory = "xo";
                };
              };

              # Required: Redis for xo-server
              services.redis.servers.xo = {
                enable = true;
                port = 6379;
              };

              # Create xo user
              users.users.xo = {
                isSystemUser = true;
                group = "xo";
                home = "/var/lib/xo";
              };
              users.groups.xo = { };

              # Example: Using libvhdi tools
              # The libvhdi package provides vhdiinfo and vhdimount
              # These are available in the system PATH when the package is installed
            }
          )
        ];
      };
    };
}
