<!-- SPDX-License-Identifier: Apache-2.0 -->
# Development Guide

## Setup

```bash
git clone https://github.com/declarative-dale/xo-nixpkg.git
cd xo-nixpkg
nix develop --accept-flake-config
```

The plain `mkShellNoCC` toolchain includes Node.js 22, Yarn classic, Valkey,
native Node build helpers, update tools, Nix linters, actionlint, ShellCheck,
and zizmor. Evaluation is pure.

```bash
valkey-server --bind 127.0.0.1
```

The XO updater enters the pure `.#updater` shell automatically when needed.

## Build and Evaluate

```bash
# Build the XO package
nix build .#xen-orchestra-ce

# Validate the in-repository FUSE3 libvhdi package
nix eval --raw .#packages.x86_64-linux.libvhdi.name
nix eval --raw .#packages.x86_64-linux.libvhdi.fuseBackend
nix build --no-link .#libvhdi

# Execute the full repository pipeline used by CI
nix run .#ci

# Pure CI-style evaluation
nix eval --accept-flake-config --json .#checks.x86_64-linux --apply builtins.attrNames
```

## Updating xen-orchestra-ce

Use the flake updater application to refresh the declarative XO source lock
from the latest upstream release commit. Nix supplies every updater dependency.
Discovery searches commits that changed upstream's root `CHANGELOG.md` and
accepts only unscoped `feat: release VERSION` markers. Scoped `feat(lite):`
commits and XO Lite tags belong to a separate upstream product and are ignored.

```bash
nix run .#update-xo-release

# Validate after update
nix run .#ci
```

The script atomically updates `nix/sources/xen-orchestra.json`. One native Nix
prefetch supplies both the source hash and source tree. Existing Yarn dependency
hashes are reused when their lock files did not change.

To refresh the source revision and affected hashes to upstream HEAD without
changing the packaged version, run:

```bash
nix run .#update-xo-upstream
```

The `latest-upstream` tag workflow uses this mode for the source-head channel.
The updater imports changed lockfiles into the Nix store before calculating
their fixed-output hashes; passing a raw store-path string would omit the
dependency from the nested build sandbox.

## Updating libvhdi

`libvhdi` is built from the compact `nix/sources/libvhdi.json` lock for
upstream's official release asset. The updater includes GitHub prereleases,
accepts only numeric date versions, requires the matching tarball, and refuses
downgrades. A flake input is deliberately not used because the asset URL embeds
its release version and therefore cannot discover its successor.

```bash
nix run --accept-flake-config .#update-libvhdi
nix build --accept-flake-config --no-link .#libvhdi
```

## Testing

```bash
# Smoke test XO binary
nix build .#xen-orchestra-ce
./result/bin/xo-server --help

# Validate libvhdi and its FUSE3 linkage
nix eval --raw .#packages.x86_64-linux.libvhdi.name
nix eval --raw .#packages.x86_64-linux.libvhdi.fuseBackend
nix build --no-link .#libvhdi
```

## Syncing with NiXOA Core

When syncing package changes with core:

```bash
# In core repo
git log --oneline pkgs/xen-orchestra-ce/

# Compare package definitions
diff -u /path/to/NiXOA/core/pkgs/xen-orchestra-ce/default.nix \
        /path/to/xen-orchestra-ce-nix/default.nix
```

Then:
1. Merge relevant package changes.
2. Re-run checks and smoke tests.
3. Update `CHANGELOG.md` and `VERSION-SYNC.md`.

## Release Workflow

Repository releases and packaged upstream versions are independent:

```bash
nix eval --raw .#lib.projectVersion
nix eval --raw .#xen-orchestra-ce.version
```

To prepare a project release:

1. Set the semantic version in `VERSION`.
2. Add the dated release entry to `CHANGELOG.md`.
3. Confirm `nix run --accept-flake-config .#ci` passes.
4. Commit and push through the protected `main` workflow.

After the gated main build succeeds, automation creates the immutable project
tag, advances `latest`, and points `stable` at the preceding project release.
The first independent project release initializes `stable` to that release.
The same gated job idempotently publishes the semantic-version tag as a GitHub
Release using only that tagged commit's matching changelog section. Re-running
the workflow never rewrites an existing tag or duplicates a published release.
