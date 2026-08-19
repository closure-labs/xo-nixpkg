<!-- SPDX-License-Identifier: Apache-2.0 -->
# xo-nixpkg

Reproducible Nix packages for Xen Orchestra Community Edition and libvhdi.
The project releases independently as `v0.8.0`; each package keeps its own
upstream version.

## Quick start

Build either package directly from GitHub:

```bash
nix build --accept-flake-config \
  github:declarative-dale/xo-nixpkg#xen-orchestra-ce
nix build --accept-flake-config \
  github:declarative-dale/xo-nixpkg#libvhdi
```

Or add the flake as an input:

```nix
{
  inputs.xo-nixpkg.url = "github:declarative-dale/xo-nixpkg";

  outputs = { nixpkgs, xo-nixpkg, ... }: {
    nixosConfigurations.example = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [{
        environment.systemPackages = [
          xo-nixpkg.packages.x86_64-linux.xen-orchestra-ce
          xo-nixpkg.packages.x86_64-linux.libvhdi
        ];
      }];
    };
  };
}
```

## Develop

```bash
git clone https://github.com/declarative-dale/xo-nixpkg.git
cd xo-nixpkg
nix develop --accept-flake-config
nix run --accept-flake-config .#ci
```

Inspect the project and package versions independently:

```bash
nix eval --raw .#lib.projectVersion
nix eval --raw .#xen-orchestra-ce.version
```

## Release and upstream channels

The immutable `v*` tags are project releases. The moving `latest` and `stable`
tags select project release revisions, while `latest-upstream` rebuilds the
current package definition against `vatesfr/xen-orchestra`'s `master` branch.
Use `latest-upstream` for development and advanced troubleshooting between
packaged upstream releases:

```bash
nix build --accept-flake-config \
  github:declarative-dale/xo-nixpkg/latest-upstream#xen-orchestra-ce
```

As a flake input:

```nix
inputs.xo-nixpkg.url =
  "github:declarative-dale/xo-nixpkg/latest-upstream";
```

The workflow moves `latest-upstream` only after the package builds
successfully. Because it is a moving development tag, pin the resolved commit
in `flake.lock` when reproducing a specific investigation.

## Documentation

- [Documentation index](docs/index.md)
- [Advanced package and flake configuration](docs/configuration.md)
- [Development and source updates](docs/development.md)
- [Testing and CI contracts](docs/testing.md)
- [Preparing packages for nixpkgs](docs/nixpkgs-submission.md)

Licensed under [Apache-2.0](LICENSE).
