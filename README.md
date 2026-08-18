<!-- SPDX-License-Identifier: Apache-2.0 -->
# xen-orchestra-ce-nix

Nix packages for [Xen Orchestra Community Edition](https://xen-orchestra.com) and [libvhdi](https://github.com/libyal/libvhdi), structured for eventual submission to nixpkgs.

## Packages

- **xen-orchestra-ce**: Full web-based management interface for XCP-ng/XenServer
- **libvhdi**: FUSE3 library and tools to access VHD/VHDX image formats, built from an npins-pinned official release asset

## Usage

### With Flakes

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    xo-ce-nix.url = "git+ssh://git@codeberg.org/NiXOA/xen-orchestra-ce.git";
  };

  outputs = { self, nixpkgs, xo-ce-nix }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        {
          environment.systemPackages = [
            xo-ce-nix.packages.x86_64-linux.xen-orchestra-ce
            xo-ce-nix.packages.x86_64-linux.libvhdi
          ];
        }
      ];
    };
  };
}
```

## Development

```bash
# Enter development shell
nix develop

# Build the XO package
nix build .#xen-orchestra-ce

# Build libvhdi and run its upstream/install/linkage checks
nix eval --raw .#packages.x86_64-linux.libvhdi.name
nix eval --raw .#packages.x86_64-linux.libvhdi.fuseBackend
nix build --no-link .#libvhdi

# Run the same complete, flake-defined pipeline as CI
nix run .#ci
```

## CI Binary Cache

The workflow YAML delegates validation, publication, tagging, update discovery,
and trusted automation to flake applications. GitHub Actions installs
Determinate Nix and configures the public
`xen-orchestra-ce` Cachix cache read-only before builds. On `main`,
`CACHIX_AUTH_TOKEN` is required and the CI workflow explicitly pushes only the
realized Xen Orchestra and libvhdi closures after the stable `CI gate` succeeds.
This avoids uploading fetched source tarballs or other incidental store paths
created during evaluation or builds while keeping the final package closure
available to NiXOA core.

## Updating Sources

### Update xen-orchestra-ce

```bash
# Automatically updates version, src.hash, and yarnOfflineCache.hash
# from the latest upstream release commit.
nix run .#update-xo-release

# Track upstream source HEAD without changing version.
nix run .#update-xo-upstream

# Validate evaluation
nix run .#ci
```

### Update libvhdi

```bash
# Discover numeric-date releases (including prereleases), pin the matching
# official release asset atomically, and reject downgrades or malformed assets.
nix run --accept-flake-config .#update-libvhdi

# Validate the package and exclusive libfuse3 linkage
nix build --accept-flake-config --no-link .#libvhdi
```

## Nixpkgs Submission

xen-orchestra-ce is maintained here as `default.nix`.

When preparing a nixpkgs PR, copy it to:
- `pkgs/by-name/xe/xen-orchestra-ce/package.nix`

See [docs/nixpkgs-submission.md](docs/nixpkgs-submission.md) for details.

## Relationship to NiXOA Core

This repository is synced with NiXOA core using a parallel sync strategy. Keep [VERSION-SYNC.md](VERSION-SYNC.md) current when package logic changes.

## License

Apache-2.0 - See [LICENSE](LICENSE)

## Related Projects

- [NiXOA](https://codeberg.org/NiXOA) - Full NixOS deployment system for Xen Orchestra
- [Xen Orchestra](https://github.com/vatesfr/xen-orchestra) - Upstream project
- [libvhdi](https://github.com/libyal/libvhdi) - Upstream VHD/VHDX library

## Maintainers

- Dale Morgan
