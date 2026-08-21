<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Publish a reproducible supply assertion plus SPDX 2.3 and CycloneDX 1.5
  runtime-closure documents for every Xen Orchestra channel. The assertion
  retains the exact protected store closure and is distributed through the
  existing signed Cachix cache for downstream verification.

## [0.9.0] - 2026-08-20

### Changed

- Model Xen Orchestra's `latest`, `stable`, and `rolling` channels as package
  outputs backed by immutable flake inputs, replacing mutable channel Git tags.
- Replace daily build-and-retry automation with standing release and rolling
  candidate pull requests whose normal CI builds all affected channel outputs.
- Replace mutable XO package fields and the single-purpose npins loader with
  pure flake-visible, atomically updated source locks.
- Detect normal XO releases through root-changelog commits, explicitly exclude
  XO Lite releases, and reuse unchanged Yarn dependency hashes during updates.
- Split repository policy and fixture validation into independently buildable
  flake checks with Nix-provided dependencies.
- Use native Nix source prefetching and skip package builds and update pull
  requests when scheduled discovery finds no source change.
- Remove Magic Nix Cache and publish the exact schema-v2 package plan from the
  already validated protected-main runner.
- Publish immutable semantic-version tags as idempotent GitHub Releases using
  the matching changelog section stored in the gated tagged commit.
- Verify an existing immutable release is published and still points at the
  expected project tag before treating publication as complete.
- Replace the schema-v1 attribute validator with a clean-break schema-v2 plan
  runner that records output manifests and materializes links atomically.
- Move GitHub source and lock pull-request creation behind Nix-provided apps,
  deferred GitHub App tokens, and canonical updater identity validation.

### Fixed

- Publish every selected Xen Orchestra channel closure without imposing the
  former two-output limit; include `libvhdi` through those closures instead of
  treating it as a separate final publication target.

## [0.8.0] - 2026-08-18

### Added

- Add an npins format-8 source for the official libvhdi release asset, with
  upstream tests, install checks, and exclusive FUSE3 linkage validation.
- Add trusted update queues, weekly grouped dependency and input refreshes, a
  checked-in main ruleset, and shared GitHub and Forgejo update automation.
- Export a reusable pure flake-attribute CI planner and Nix-wrapped validator
  that validates target contracts, isolates builds, and collects all failures.
- Add a repository-owned `VERSION` so project releases advance independently
  from the packaged Xen Orchestra version.

### Changed

- Provide a pure `mkShellNoCC` development toolchain with Node.js 22, Yarn,
  Valkey, update tools, and repository linters.
- Consolidate validation, publication, tagging, release discovery, and trusted
  queue policy behind Nix-provided flake apps.
- Require an up-to-date `CI gate`, pin workflow actions, share job-local Nix
  results, and publish final XO and libvhdi closures from protected `main`.
- Use `v0.8.0` for the project release while continuing to report the packaged
  Xen Orchestra release through `packages.x86_64-linux.xen-orchestra-ce.version`.
- Organize the README around quick-start commands and link advanced
  configuration, development, testing, and nixpkgs guidance from `docs/`.

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
