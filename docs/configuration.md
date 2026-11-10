<!-- SPDX-License-Identifier: Apache-2.0 -->
# Configuration Guide

## Pin the flake

Use a locked flake input for reproducible deployments:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    xo-nixpkg.url = "github:closure-labs/xo-nixpkg";
  };
}
```

Commit the resulting `flake.lock`. The input exposes these primary packages on
`x86_64-linux`:

- `packages.x86_64-linux.latest`: newest official XO release
- `packages.x86_64-linux.stable`: newest supported predecessor of the latest
  official XO release
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
- `packages.x86_64-linux.automation-runtime`: packaged CI, publication,
  trusted-queue, and updater applications

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

Xen Orchestra's upstream `fuse-native` addon still requires libfuse2, supplied
only to XO through the [pinned compatibility leaf](../nix/fuse2-compat/README.md).
FUSE 2 is end-of-life; this does not replace the host's FUSE 3 configuration or
automatically install a privileged mount helper. Libvhdi's
`vhdimount` uses libfuse3. A host running both should enable the kernel FUSE
device and grant its service users the required FUSE permissions.

## Binary cache

The flake declares the public `xen-orchestra-ce.cachix.org` substituter and its
trusted key from the single `lib.binaryCache` definition. Pass
`--accept-flake-config` when consuming it interactively. The shared GitHub Nix
setup enables `accept-flake-config`, so the cache is trusted from the first
`nix run`. A NixOS host can instead declare the same substituter and key in its
trusted Nix configuration.

GitHub Actions consumes the same public cache graph. The protected-main
lifecycle publishes only package closures selected by the path classifier and
does so in the validation job's existing Nix store. GitHub-hosted runners are
ephemeral, so CI does not garbage-collect an isolated local store after the
job. No runner-local or Determinate substituter is required.

The pinned installer action uses `determinate: false` and `flakehub: false` to
skip action-managed FlakeHub authentication. It separately passes
`extra-args: --determinate` and pins `source-tag` to retain Determinate Nix and
`determinate-nixd` for the repository's hash-repair task. The installer explicitly
prioritizes `--determinate` over the action's `--prefer-upstream-nix` fallback in
both pinned releases (3.21.9 and 3.24.1). See the
[installer distribution selector](https://github.com/DeterminateSystems/nix-installer/blob/v3.24.1/src/settings.rs)
and the [action login branch](https://github.com/DeterminateSystems/nix-installer-action/blob/9383ce2bf08796b65508822f5982f49151badc4e/src/index.ts).

Clearing OIDC environment variables in YAML is insufficient: GitHub's Node
action runner injects fresh OIDC values after applying that environment. The
installer's explicit login toggle works even in attestation jobs with OIDC;
job permissions are unchanged. These workflows use Ubuntu systemd runners,
whose daemon setup is handled by the installer. Action-managed hash annotations
are disabled in this mode; `ci/fix-nix-hashes.sh` still uses the installed daemon.

Determinate Nixd also adds `install.determinate.systems` when logged out. That
endpoint proxies FlakeHub Cache, so disabling login alone is insufficient.
The generated system config includes `nix.custom.conf` before its cache additions;
installer `extra-conf` therefore cannot be the final cache policy.

After each installer, CI preserves the current `NIX_CONFIG` and appends a public
`substituters` reset with no extra substituters, using GitHub's environment file
without logging the configuration. Nix applies this environment layer after
system configuration and sends it as an override to the daemon for the trusted
runner. The repository flake can still add its existing Cachix cache and key.
Environment-isolated diagnostics either set explicit public cache options or
disable substitution; the retained-restore bootstrap also resets its cache list.

The shared setup explicitly selects `https://cache.nixos.org` for bootstrap and
checks the effective substituters from Nix JSON before evaluating the repository.
A trailing slash on the public cache URL is accepted; additional caches are not.
The JSON is piped privately to the verifier, never logged or saved. Failures report
only cache hostnames, not other configuration or credentials. The flake
then adds the existing public Cachix cache and signing key. Unexpected inherited
caches fail setup rather than silently querying FlakeHub. No FlakeHub cache action,
credentials, or uploads are used; publication remains on the existing Cachix path.

The three supply-protector outputs are ordinary Nix store outputs in the same
publication plan. Their `assertion.json` identifies the exact XO store path,
channel, upstream revision, closure-graph digest, document digests, and Cachix
trust root. The SPDX and CycloneDX documents model the exported runtime
reference graph without querying the Nix daemon from a sandboxed builder. A
consumer that substitutes the assertion through the configured Cachix key can
therefore compare its selected XO output with the asserted store path before
building a broader system-level SBOM or provenance attestation.

Maestro separately retains `https://install.determinate.systems` for users
loading its flake from an existing vanilla-nixpkgs NixOS VM. That consumer
cache avoids compiling Determinate Nix and is not duplicated here because
xo-nixpkg does not build Maestro's Determinate input.

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
  github:closure-labs/xo-nixpkg#run-ci-plan -- \
  --plan lib.ciPlans.x86_64-linux.validation
```

The runner evaluates the selected plan once, verifies schema version 2 and
target uniqueness, builds each attribute in a separate process, and reports
all target results before returning.

## Reuse the CI classifier contract

The schema-v2 hosted classifier uses `ci/classifier.json` as its versioned
source of truth, exported as `lib.ciClassifier`. Nix imports the same target
catalog to construct `lib.ciPlans`, while the classifier resolves changed
paths, dependency edges, validation plans, publication plans, and release
lifecycle state without installing Nix. Unknown paths and invalid Git ancestry
select the complete validation plan.

`classify-ci` emits the schema-v2 lifecycle document. `ci` and `publish`
consume its embedded plans, and `run-ci-plan` validates and executes a reusable
pure `lib.ciPlans` value. Classification and final gates stay on
`ubuntu-slim`; Nix is installed only for jobs that evaluate or build flake
outputs. The `automation-runtime` package retains all packaged commands so its
closure can be reused by scheduled workflows through Cachix.

Version 0.10.0 removed the unused schema-v1 workflow library interfaces and
the `prepare-ci` and `ci-gate` adapters. Downstream consumers should replace
them with `lib.ciClassifier`, `lib.ciPlans`, `classify-ci`, `run-ci-plan`,
`ci`, and `publish` as appropriate.

Imperative network, Git, release, source-lock mutation, plan execution, and
Cachix operations remain checked-in shell programs under `ci/` and `scripts/`.
Fixture shells remain where fake commands, temporary repositories, or injected
failures are the behavior under test.

The validation workflow bootstraps its three build jobs using the same pinned
vendor installer and public-cache guard directly, with no stored fetch token.
This allows repairing a broken setup action without executing candidate setup
code or depending on the protected base's broken copy. Controller checkout refs,
protected preflight/runtime execution, and the no-certification path for proposed
workflow changes remain unchanged.
