<!-- SPDX-License-Identifier: Apache-2.0 -->
# Development Guide

## Setup

```bash
git clone ssh://git@codeberg.org/NiXOA/xen-orchestra-ce.git
cd xen-orchestra-ce
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

Use the flake updater application to refresh version and hashes in `default.nix`
from the latest upstream release commit. Nix supplies every updater dependency.
Release discovery scans paginated upstream commit history and stops early when
the package already points at the latest release commit. Set
`XO_NIXPKG_RELEASE_SCAN_PAGES` to override the default scan depth.

```bash
nix run .#update-xo-release

# Validate after update
nix run .#ci
```

The script updates:
- `version`
- `src.rev`
- `src.hash`
- `yarnOfflineCache.hash`

To refresh only `src.rev`, `src.hash`, and `yarnOfflineCache.hash` to the
latest upstream source commit without changing `version`, run:

```bash
nix run .#update-xo-upstream
```

The `latest-upstream` tag workflow uses this mode for the source-head channel.

## Updating libvhdi

`libvhdi` is built from an npins format-8 URL pin to upstream's official
release asset. The updater includes GitHub prereleases, accepts only numeric
date versions, requires the matching tarball, and refuses downgrades.

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

1. Update `CHANGELOG.md`.
2. Confirm `nix run .#ci` passes.
3. Commit and push.
4. Tag release if needed.
