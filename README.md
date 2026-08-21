<!-- SPDX-License-Identifier: Apache-2.0 -->
# xo-nixpkg

Reproducible Nix packages for Xen Orchestra Community Edition and libvhdi.
The project releases independently as `v0.9.5`; each package keeps its own
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

## Xen Orchestra channels

Channels are package outputs of one locked repository revision, not moving Git
tags:

- `latest` is the newest official Xen Orchestra release.
- `stable` is the preceding official Xen Orchestra release.
- `rolling` follows the newest upstream `master` commit that has passed this
  repository's pull-request CI. It is intended for troubleshooting and
  development.

`xen-orchestra-ce`, `xen-orchestra-ce-latest`,
`xen-orchestra-ce-stable`, and `xen-orchestra-ce-rolling` are descriptive
aliases. `latest-upstream` is a compatibility output alias for `rolling`.
Select a channel by package attribute:

```bash
nix build --accept-flake-config github:declarative-dale/xo-nixpkg#latest
nix build --accept-flake-config github:declarative-dale/xo-nixpkg#stable
nix build --accept-flake-config github:declarative-dale/xo-nixpkg#rolling
nix build --accept-flake-config \
  github:declarative-dale/xo-nixpkg#supply-protector-latest
```

As a flake input, keep one locked input and select its output:

```nix
inputs.xo-nixpkg.url = "github:declarative-dale/xo-nixpkg";

environment.systemPackages = [
  inputs.xo-nixpkg.packages.x86_64-linux.stable
];
```

The immutable project `v*` tags remain available for repository releases. No
automation moves `latest`, `stable`, or `latest-upstream` Git tags. Commit the
resolved `flake.lock` when reproducing a rolling-channel investigation.

Each channel has a matching `supply-protector-<channel>` output containing a
reproducible closure assertion, the exported Nix reference graph, and SPDX 2.3
and CycloneDX 1.5 documents. `supply-protector` selects `latest`. Protected
main publishes these outputs through the signed public Cachix cache alongside
the packages they describe.

## Documentation

- [Documentation index](docs/index.md)
- [Advanced package and flake configuration](docs/configuration.md)
- [Development and source updates](docs/development.md)
- [Testing and CI contracts](docs/testing.md)
- [Preparing packages for nixpkgs](docs/nixpkgs-submission.md)

Licensed under [Apache-2.0](LICENSE).
