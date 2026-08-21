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

- `packages.x86_64-linux.latest`: newest official XO release
- `packages.x86_64-linux.stable`: preceding official XO release
- `packages.x86_64-linux.rolling`: newest admitted upstream `master` commit
- `packages.x86_64-linux.supply-protector-latest`: signed-cache supply
  assertion and closure documents for `latest`
- `packages.x86_64-linux.supply-protector-stable`: matching `stable` supply
  assertion
- `packages.x86_64-linux.supply-protector-rolling`: matching `rolling` supply
  assertion
- `packages.x86_64-linux.xen-orchestra-ce`: compatibility alias for `latest`
- `packages.x86_64-linux.libvhdi`
- `packages.x86_64-linux.flake-plan-runner`

The descriptive aliases `xen-orchestra-ce-latest`,
`xen-orchestra-ce-stable`, and `xen-orchestra-ce-rolling` resolve to the same
three derivations. Channels are outputs of the locked input, so switching
channels does not require following a moving Git tag.

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

GitHub Actions consumes the same public cache graph. The protected-main
lifecycle publishes only package closures selected by the path classifier and
does so in the validation job's existing Nix store. GitHub-hosted runners are
ephemeral, so CI does not garbage-collect an isolated local store after the
job. No runner-local or Determinate substituter is required.

The three supply-protector outputs are ordinary Nix store outputs in the same
publication plan. Their `assertion.json` identifies the exact XO store path,
channel, upstream revision, closure-graph digest, document digests, and Cachix
trust root. The SPDX and CycloneDX documents model the exported runtime
reference graph without querying the Nix daemon from a sandboxed builder. A
consumer that substitutes the assertion through the configured Cachix key can
therefore compare its selected XO output with the asserted store path before
building a broader system-level SBOM or provenance attestation.

NiXOA Core separately retains `https://install.determinate.systems` for users
loading its flake from an existing vanilla-nixpkgs NixOS VM. That consumer
cache avoids compiling Determinate Nix and is not duplicated here because
xo-nixpkg does not build Core's Determinate input.

## Inspect source locks

Both upstream pins are exposed as pure flake data:

```bash
nix eval --json .#lib.sourcePins
```

The XO lock records the `latest`, `stable`, and `rolling` revisions and their
dependency hashes. The corresponding flake inputs provide Nix-native immutable
source locks. The libvhdi lock records the exact official release tarball. XO
Lite releases are intentionally not represented.

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

The hosted workflow's faster event adapter uses `ci/classifier.json` as its
versioned source of truth. Nix imports the same target catalog to construct
`lib.ciPlans`, while the adapter resolves changed paths, dependency edges, and
publication targets without installing Nix. Unknown paths and invalid Git
ancestry select the complete validation plan.

The `prepare-ci` and `ci-gate` apps are generated runtime adapters: they read
only the selected flake and non-secret GitHub context, delegate policy to those
pure functions, and optionally write the existing `GITHUB_OUTPUT` format.
Composed apps invoke packaged sibling executables from their Nix closures.
`classify-ci` exposes the hosted adapter for local fixtures and diagnostics.

Imperative network, Git, release, source-lock mutation, plan execution, and
Cachix operations remain checked-in shell programs under `ci/` and `scripts/`.
Fixture shells remain where fake commands, temporary repositories, or injected
failures are the behavior under test.
