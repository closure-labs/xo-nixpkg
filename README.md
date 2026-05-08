<!-- SPDX-License-Identifier: Apache-2.0 -->
# xen-orchestra-ce-nix

Nix packages for [Xen Orchestra Community Edition](https://xen-orchestra.com) and [libvhdi](https://github.com/declarative-dale/libvhdi-nixpkg), structured for eventual submission to nixpkgs.

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

# Build the XO package
nix build .#xen-orchestra-ce

# Validate the published libvhdi input
nix eval --raw .#packages.x86_64-linux.libvhdi.name
nix path-info .#libvhdi \
  --option extra-substituters 'https://libvhdi-nixpkg.cachix.org' \
  --option extra-trusted-public-keys 'libvhdi-nixpkg.cachix.org-1:HvYHKZcfczn2nGfCmd7F21E/MDZrlaXtN3p9mWAZT/4='

# Evaluate all outputs
nix flake check --all-systems --no-build
```

## CI Binary Cache

GitHub Actions configures Cachix read-only before builds when
`CACHIX_CACHE_NAME` is set. If `CACHIX_AUTH_TOKEN` is also configured, each
workflow explicitly pushes only the `result` path after `nix build` succeeds.
This avoids uploading fetched source tarballs or other incidental store paths
created during evaluation or builds.

The `libvhdi` input is consumed from
[`declarative-dale/libvhdi-nixpkg`](https://github.com/declarative-dale/libvhdi-nixpkg)
and should be substituted from its public Cachix cache:

- substituter: `https://libvhdi-nixpkg.cachix.org`
- trusted key: `libvhdi-nixpkg.cachix.org-1:HvYHKZcfczn2nGfCmd7F21E/MDZrlaXtN3p9mWAZT/4=`

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

### Bump libvhdi-nixpkg release tag

```bash
# Edit inputs.libvhdi.url in flake.nix to the new release tag, then refresh
# the lock file.
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
- [libvhdi-nixpkg](https://github.com/declarative-dale/libvhdi-nixpkg) - Published libvhdi package flake

## Maintainers

- Dale Morgan
