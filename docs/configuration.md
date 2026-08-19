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
- `packages.x86_64-linux.flake-plan-runner`

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

GitHub Actions consumes the same public cache graph and explicitly publishes
the final package plan only after protected-main validation. No runner-local or
Determinate substituter is required for package evaluation.

NiXOA Core separately retains `https://install.determinate.systems` for users
loading its flake from an existing vanilla-nixpkgs NixOS VM. That consumer
cache avoids compiling Determinate Nix and is not duplicated here because
xo-nixpkg does not build Core's Determinate input.

## Inspect source locks

Both upstream pins are exposed as pure flake data:

```bash
nix eval --json .#lib.sourcePins
```

The XO lock records its selected normal-release commit and dependency hashes.
The libvhdi lock records the exact official release tarball. XO Lite releases
are intentionally not represented.

## Reuse the CI plan contract

Downstream flakes can declare their own pure target plans with the exported
planner:

```nix
let
  mkPlan = inputs.xo-nixpkg.lib.mkCiPlan;
in {
  lib.ciPlans.x86_64-linux.validation = mkPlan {
    name = "example-validation";
    targets = [
      { name = "repository"; attribute = "checks.x86_64-linux.repository"; }
      { name = "default"; attribute = "packages.x86_64-linux.default"; }
    ];
  };
}
```

Run the plan with the packaged validator:

```bash
nix run --accept-flake-config \
  github:declarative-dale/xo-nixpkg#run-ci-plan -- \
  --plan lib.ciPlans.x86_64-linux.validation
```

The runner evaluates the selected plan once, verifies schema version 2 and
target uniqueness, builds each attribute in a separate process, and reports
all target results before returning.

## Reuse the CI workflow contract

`lib.mkCiWorkflow` combines named plans with event/ref conditions and declares
which enabled jobs must pass the gate. This repository exposes the concrete
definition at `lib.ciWorkflows.x86_64-linux`. Downstream flakes can call
`lib.prepareCiWorkflow` to produce the versioned prepared schema for an event,
then call `lib.evaluateCiWorkflowGate` with GitHub-style job results to obtain
the gate decision and required-job summary. Both operations are pure Nix
functions and reject malformed workflow data.

The `prepare-ci` and `ci-gate` apps are generated runtime adapters: they read
only the selected flake and non-secret GitHub context, delegate policy to those
pure functions, and optionally write the existing `GITHUB_OUTPUT` format.
Composed apps invoke packaged sibling executables from their Nix closures.

Imperative network, Git, release, source-lock mutation, plan execution, and
Cachix operations remain checked-in shell programs under `ci/` and `scripts/`.
Fixture shells remain where fake commands, temporary repositories, or injected
failures are the behavior under test.
