<!-- SPDX-License-Identifier: Apache-2.0 -->
# Development Guide

## Setup

```bash
git clone ssh://git@codeberg.org/NiXOA/xen-orchestra-ce.git
cd xen-orchestra-ce
nix develop
```

## Build and Evaluate

```bash
# Build packages
nix build .#xen-orchestra-ce
nix build .#libvhdi

# Evaluate flake outputs on all declared systems
nix flake check --all-systems --no-build
```

## Updating xen-orchestra-ce

Use the updater script to refresh version and hashes in `default.nix` from the
latest upstream release commit.

```bash
./scripts/update.sh --release

# Validate after update
nix flake check --all-systems --no-build
```

The script updates:
- `version`
- `src.rev`
- `src.hash`
- `yarnOfflineCache.hash`

To refresh only `src.rev`, `src.hash`, and `yarnOfflineCache.hash` to the
latest upstream source commit without changing `version`, run:

```bash
./scripts/update.sh --upstream
```

The `latest-upstream` tag workflow uses this mode for the source-head channel.

## Updating libvhdi Input

`libvhdi` is consumed as a flake input from `NiXOA/libvhdi`.

```bash
nix flake lock --update-input libvhdi
nix flake check --all-systems --no-build
```

## Testing

```bash
# Smoke test XO binary
nix build .#xen-orchestra-ce
./result/bin/xo-server --help

# Smoke test libvhdi binary
nix build .#libvhdi
./result/bin/vhdiinfo -V
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
2. Confirm `nix flake check --all-systems --no-build` passes.
3. Commit and push.
4. Tag release if needed.
