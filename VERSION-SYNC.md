<!-- SPDX-License-Identifier: Apache-2.0 -->
# Version Sync Tracking

This document tracks synchronization between NiXOA core and this standalone package repository.

## Current Status

| Repository | Version | Last Sync | Core Version | Nixpkgs Status |
|------------|---------|-----------|--------------|----------------|
| xo-nixpkg | v0.8.0 | 2026-08-18 | v1.1.2+ | Packaging maintained here |

## Sync History

### 2026-08-18: Independent project releases (v0.8.0)
- Introduced a repository-owned project version
- Kept Xen Orchestra package versions aligned with their upstream release
- Integrated the reusable flake-attribute CI planner consumed by core
- Organized quick-start, configuration, development, and testing documentation

### 2026-02-27: Submission-readiness cleanup (v1.1.0)
- Flattened package layout to top-level `default.nix`
- Moved helper scripts to `scripts/`
- Updated updater workflows to use `scripts/update.sh`
- Refreshed docs to match current flake outputs and package structure

### 2026-01-10: Initial repository structure (v1.0.0)
- Created standalone repository structure
- Synced packages from NiXOA core v0.5

## Sync Procedure

### Core -> Standalone

When syncing Xen Orchestra package changes from core:

```bash
cd /path/to/NiXOA/core
git log --oneline pkgs/xen-orchestra-ce/

diff -u /path/to/NiXOA/core/pkgs/xen-orchestra-ce/default.nix \
        /path/to/xen-orchestra-ce-nix/default.nix
```

Then:
1. Merge derivation changes.
2. Re-run checks.
3. Update `CHANGELOG.md` and this file.

### Standalone -> Core

When propagating standalone changes back to core:
1. Compare `default.nix` logic.
2. Port any helper script changes under `scripts/`.
3. Validate in core system build.
4. Update core changelog as needed.

## Sync Checklist

- [ ] Compare package logic with diff
- [ ] Update source revision/hash as needed
- [ ] Update yarn offline cache hash as needed
- [ ] Run `nix flake check --all-systems --no-build`
- [ ] Build and smoke test `xen-orchestra-ce`
- [ ] Validate the npins-backed `libvhdi` package and exclusive FUSE3 linkage
- [ ] Update `CHANGELOG.md`
- [ ] Update `VERSION-SYNC.md`
