<!-- SPDX-License-Identifier: Apache-2.0 -->
# Configuration Guide

## Pin the flake

Use a locked flake input for reproducible deployments:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    xo-nixpkg.url = "github:declarative-dale/xo-nixpkg";
  };
}
```

Commit the resulting `flake.lock`. The input exposes these primary packages on
`x86_64-linux`:

- `packages.x86_64-linux.xen-orchestra-ce`
- `packages.x86_64-linux.libvhdi`
- `packages.x86_64-linux.flake-attribute-validator`

## Install packages on NixOS

Select packages directly from the locked input:

```nix
{ inputs, ... }:
{
  environment.systemPackages = [
    inputs.xo-nixpkg.packages.x86_64-linux.xen-orchestra-ce
    inputs.xo-nixpkg.packages.x86_64-linux.libvhdi
  ];
}
```

Xen Orchestra's rebuilt `fuse-native` addon uses libfuse2. Libvhdi's
`vhdimount` uses libfuse3. A host running both should enable the kernel FUSE
device and grant its service users the required FUSE permissions.

## Binary cache

The flake declares the public `xen-orchestra-ce.cachix.org` substituter and its
trusted key. Pass `--accept-flake-config` when consuming it interactively. A
NixOS host can instead declare the same substituter and key in its trusted Nix
configuration.

## Reuse the CI plan contract

Downstream flakes can declare their own pure target plans with the exported
planner:

```nix
let
  mkPlan = inputs.xo-nixpkg.lib.mkFlakeAttributePlan;
in {
  lib.ciPlans.x86_64-linux.validation = mkPlan {
    name = "example-validation";
    targets = [
      "checks.x86_64-linux.repository"
      "packages.x86_64-linux.default"
    ];
  };
}
```

Run the plan with the packaged validator:

```bash
nix run --accept-flake-config \
  github:declarative-dale/xo-nixpkg#validate-ci-plan -- \
  --plan lib.ciPlans.x86_64-linux.validation
```

The validator evaluates the selected plan once, verifies schema version 1 and
target uniqueness, builds each attribute in a separate process, and reports
all target results before returning.
