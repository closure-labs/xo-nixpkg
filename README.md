<!-- SPDX-License-Identifier: Apache-2.0 -->
# xen-orchestra-ce-nix

Nix packages for [Xen Orchestra Community Edition](https://xen-orchestra.com) and [libvhdi](https://codeberg.org/NiXOA/libvhdi), structured for eventual submission to nixpkgs.

## Packages

- **xen-orchestra-ce**: Full web-based management interface for XCP-ng/XenServer
- **libvhdi**: Library and tools to access VHD/VHDX image formats (provided via pinned flake input)

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

# Build packages
nix build .#xen-orchestra-ce
nix build .#libvhdi

# Evaluate all outputs
nix flake check --all-systems --no-build
```

## CI Binary Cache

GitHub Actions configures Cachix read-only before builds when
`CACHIX_CACHE_NAME` is set. If `CACHIX_AUTH_TOKEN` is also configured, each
workflow explicitly pushes only the `result` path after `nix build` succeeds.
This avoids uploading fetched source tarballs or other incidental store paths
created during evaluation or builds.

## Updating Sources

### Update xen-orchestra-ce

```bash
# Automatically updates version, src.hash, and yarnOfflineCache.hash
# from the latest upstream release commit.
./scripts/update.sh --release

# Track upstream source HEAD without changing version.
./scripts/update.sh --upstream

# Validate evaluation
nix flake check --all-systems --no-build
```

### Update libvhdi input

```bash
# Move libvhdi input to latest pinned revision/tag
nix flake lock --update-input libvhdi

# Validate evaluation
nix flake check --all-systems --no-build
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
- [libvhdi](https://codeberg.org/NiXOA/libvhdi) - Standalone libvhdi package repo

## Maintainers

- Dale Morgan
