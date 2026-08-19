<!-- SPDX-License-Identifier: Apache-2.0 -->
# Testing Guide

## Local Checks

```bash
# Evaluate all outputs (no builds)
nix flake check --all-systems --no-build

# Build the XO package
nix build .#xen-orchestra-ce

# Validate the source-locked libvhdi package and FUSE3 linkage
nix eval --raw .#packages.x86_64-linux.libvhdi.name
nix eval --raw .#packages.x86_64-linux.libvhdi.fuseBackend
nix build --no-link .#libvhdi

# Inspect or run the exact independent attribute-build plan used by CI
nix eval --json .#lib.ciPlans.x86_64-linux.validation
nix run .#run-ci-plan -- \
  --plan lib.ciPlans.x86_64-linux.validation

# Inspect the workflow definition, or prepare it for a pull request
nix eval --json .#lib.ciWorkflows.x86_64-linux
GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1/merge \
  nix run .#prepare-ci

# Inspect the fast lifecycle classifier (local events select the full plan)
nix run .#classify-ci
```

## Runtime Smoke Tests

### xen-orchestra-ce

```bash
nix build .#xen-orchestra-ce
./result/bin/xo-server --help
./result/bin/xo-server --version || true
```

### libvhdi

```bash
nix eval --raw .#packages.x86_64-linux.libvhdi.name
nix eval --raw .#packages.x86_64-linux.libvhdi.fuseBackend
nix build --no-link .#libvhdi
```

## Submission-Oriented Checks

Before opening nixpkgs PRs:

```bash
# Evaluate current flake
nix flake check --all-systems --no-build

# Optional: dry-run package build planning
nix build .#xen-orchestra-ce --dry-run
nix build --no-link .#libvhdi
```

## Common Failures

### Yarn Hash Mismatch

If `yarnOfflineCache` hash mismatches:

```bash
./scripts/update.sh --release
```

### Source Hash Mismatch

If the XO source hash needs refreshing:

```bash
nix run .#update-xo-release
```

### Broken Symlinks in Output

The package currently removes broken symlinks during `preFixup`:

```nix
preFixup = ''
  find "$out/libexec/xen-orchestra" -xtype l -delete || true
'';
```

## CI Coverage

`ci/classifier.json` is the shared hosted-CI target graph and
`lib.ciWorkflows.x86_64-linux` remains the reusable pure workflow API. The
classifier emits one schema-v2 lifecycle document containing the exact
validation and publication plans. Workflow conditions, the lightweight gate,
`nix run .#ci`, and `nix run .#publish` consume that document directly.

Classifier fixtures cover documentation-only changes, component target
selection, dependency expansion, exact and ancestral merge-group reuse,
publication deltas, non-ancestral fail-safe behavior, and full manual runs.
The plan runner validates a supplied JSON plan without evaluating the plan a
second time, then builds each selected attribute independently so every
failure is collected. For local use, `.#ci` classifies the local event as a
full run when no prepared output is supplied. CI checks:
- package builds for `xen-orchestra-ce`
- upstream/install checks and exclusive FUSE3 linkage for `libvhdi`
- XO `fuse-native` libfuse2 linkage and absence of bundled/prebuilt FUSE files
- updater, trusted-queue, runtime-adapter, shell, and ruleset fixtures
- closure-composition checks for packaged child commands
- `nix flake check`
- basic binary execution smoke tests

`nix flake check` is the canonical aggregate check graph; there is no separate
shell test aggregator. `nix run .#ci` is the supported end-to-end entrypoint
that evaluates the flake and executes every validation-plan target.
