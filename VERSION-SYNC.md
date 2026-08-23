<!-- SPDX-License-Identifier: Apache-2.0 -->
# Version Sync Tracking

This document tracks synchronization between Maestro and this standalone package repository.

## Current Status

| Repository | Version | Last Sync | Maestro Version | Nixpkgs Status |
|------------|---------|-----------|--------------|----------------|
| xo-nixpkg | v0.9.5 | 2026-08-20 | v1.3.1-dev.0+ | Packaging maintained here |

## Sync History

### 2026-08-20: Supply assertion trust chain (v0.9.5)
- Published deterministic assertions, closure graphs, SPDX 2.3, CycloneDX 1.5, and checksums for every Xen Orchestra channel
- Distributed the supply outputs through the signed Cachix cache while retaining each exact Xen Orchestra closure as a Nix reference
- Established `supply-protector-latest` as a cryptographic dependency contract for Maestro installer attestations
- Enabled Maestro to verify the Nix store identity, Cachix trust root, and document hashes before adding a checksummed SPDX `DESCRIBED_BY` link

### 2026-08-20: Nix-native release channels (v0.9.0)
- Replaced moving channel tags with immutable `latest`, `stable`, and `rolling` package outputs
- Replaced daily build-and-retry jobs with standing release and rolling candidate pull requests
- Published all three Xen Orchestra closures from protected main, including libvhdi transitively
- Updated Maestro to select the `latest` package output by default

### 2026-08-18: Independent project releases (v0.8.0)
- Introduced a repository-owned project version
- Kept Xen Orchestra package versions aligned with their upstream release
- Integrated the reusable flake-attribute CI planner consumed by Maestro
- Organized quick-start, configuration, development, and testing documentation

### 2026-02-27: Submission-readiness cleanup (v1.1.0)
- Flattened package layout to top-level `default.nix`
- Moved helper scripts to `scripts/`
- Updated updater workflows to use `scripts/update.sh`
- Refreshed docs to match current flake outputs and package structure

### 2026-01-10: Initial repository structure (v1.0.0)
- Created standalone repository structure
- Synced packages from Maestro v0.5

## Sync Procedure

### Maestro -> Standalone

When syncing Xen Orchestra package changes from Maestro:

```bash
cd /path/to/maestro
git log --oneline pkgs/xen-orchestra-ce/

diff -u /path/to/maestro/pkgs/xen-orchestra-ce/default.nix \
        /path/to/xen-orchestra-ce-nix/default.nix
```

Then:
1. Merge derivation changes.
2. Re-run checks.
3. Update `CHANGELOG.md` and this file.

### Standalone -> Maestro

When propagating standalone changes back to Maestro:
1. Compare `default.nix` logic.
2. Port any helper script changes under `scripts/`.
3. Validate in Maestro system build.
4. Update Maestro changelog as needed.

## Sync Checklist

- [ ] Compare package logic with diff
- [ ] Update source revision/hash as needed
- [ ] Update yarn offline cache hash as needed
- [ ] Run `nix flake check --all-systems --no-build`
- [ ] Build and smoke test `xen-orchestra-ce`
- [ ] Validate the source-locked `libvhdi` package and exclusive FUSE3 linkage
- [ ] Update `CHANGELOG.md`
- [ ] Update `VERSION-SYNC.md`
