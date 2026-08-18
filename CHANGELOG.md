<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

- Package libvhdi directly from an npins format-8 pin to its official release
  asset, with FUSE3 as its only FUSE backend and upstream/install checks.
- Replace devenv with a pure `mkShellNoCC` toolchain and remove the external
  libvhdi flake, compatibility outputs, lock graph, and dedicated cache.
- Require a stable, up-to-date `CI gate`; pin actions; use job-local GitHub Nix
  caching; and publish only final XO/libvhdi closures from protected `main`.
- Add trusted update queues, weekly grouped dependency/input updates, a checked
  in main ruleset, and shared GitHub/Forgejo libvhdi update automation.
- Move validation, publication, tagging, release discovery, and trusted queue
  policy behind Nix-provided flake apps, leaving workflow YAML as thin host
  orchestration.
- Export a reusable pure flake-attribute CI planner and one Nix-wrapped
  validator that rejects malformed plans, isolates target builds, and collects
  all failures before returning.

### Fixed

- Pass the GitHub App ID expected by `actions/create-github-app-token@v3` in
  release and update workflows.
- Verify XO's rebuilt `fuse-native` addon links libfuse2 while libvhdi's
  `vhdimount` links only libfuse3, with bundled/prebuilt npm FUSE files absent.

## [v6.3.3] - 2026-04-14

<img id="latest" src="https://badgen.net/badge/channel/latest/yellow" alt="Channel: latest" />

### Bug fixes

- [Header]: Fix `Unable to connect to XO server` falshing every 30 secondes (PR [#9681](https://github.com/vatesfr/xen-orchestra/pull/9681))
- [Backups]: Fix regression on cleanVM speed (PR [#9692](https://github.com/vatesfr/xen-orchestra/pull/9692))
- [Backups]: Fix merge resume when child is disk chain (PR [#9668](https://github.com/vatesfr/xen-orchestra/pull/9668))
- [Incremental Replication]: Fix "Storage_error ([S(Illegal_transition);[[S(Activated);S(RO)];[S(Activated);S(RW)]]])" [Forum#12059](https://xcp-ng.org/forum/topic/12059/xen-orchestra-6.3.2-random-replication-failure) (PR [#9702](https://github.com/vatesfr/xen-orchestra/pull/9702))
- [Replication]: Distributed replication toggle not enabled when targetting 2 SRs (PR [#9715](https://github.com/vatesfr/xen-orchestra/pull/9715))

### Released packages

- @xen-orchestra/xapi 8.7.1
- @xen-orchestra/backups 0.71.3
- @xen-orchestra/immutable-backups 2.0.2
- @xen-orchestra/proxy 0.29.57
- xo-server 5.198.5

## [v6.2.0] - 2026-02-27

### Changed
- Updated xen-orchestra-ce packaging to `6.2.0` and refreshed source/yarn hashes for reproducible builds.
- Refreshed flake inputs and lock state (including `nixpkgs`/`libvhdi`) and removed the legacy in-repo `libvhdi` package copy.
- Improved update automation to use `scripts/update.sh` and update both source and yarn cache hashes.
- Refactored repository layout for nixpkgs submission readiness (`default.nix` at repo root, helper tooling under `scripts/`).
- Refreshed README and docs to match current flake outputs and package structure.

### Fixed
- Added TypeScript compatibility patching for `xo-server-openmetrics` build path.
- Corrected stale package metadata comments and removed placeholder maintainer comment block.

## [v6.1.1] - 2026-01-10

This release updates Xen Orchestra packaging and refreshes libvhdi integration.

### Highlights
- Updated Xen Orchestra package to `6.1.1`.
- Updated `libvhdi` packaging to the latest upstream version.
- Added `AGENTS.md` guidance for LLM-assisted workflows.
- Included CI workflow examples for monitoring upstream XO release updates.

### Notable commits
- 6468ffa: updated libvhdi to latest version
- 91c0b79: updated to 6.1.1
- a131725: added Agents.md to assist with LLM tools

### Notes
- Verified `yarnOfflineCache.hash` after source bumps to `yarn.lock` changes.
