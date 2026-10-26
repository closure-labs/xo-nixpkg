<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- Automatically admit pending CI for draft and ready PRs from the pinned Decider
  bot or live Super Admins, without granting review, merge or publication authority.

- Add default-enabled manual `export_reuse_payload` and strict runtime `XO_NIXPKG_EXPORT_REUSE_PAYLOAD` controls, independently of artifact imports. Audit-only runs still validate selected outputs and source identities while skipping reuse serialization and upload; exported receipts retain independent attestation. Retain a bounded export transport profile.

- Give CI one required security/preflight owner and pass source-, controller-, plan-, run- and attempt-bound evidence to runtime validation. Share pure security fixtures through a private derivation while retaining all 19 audit targets, standalone security coverage, bootstrap validation and independent output attestation.

- Retain successful native publication operation summaries so repeated delivery can prove zero closure materialization and destination write attempts.

- Reduce repeated decision API reads with job-local, hash-verified Git blob reuse,
  while keeping current-main metadata and human authorization checks live.
- Allow the existing weekly input updater to queue edits to either or both native
  lockfiles, retaining its exact-head checks and rejecting other changes.

- Reject obsolete proposal parents before downloading review evidence, and refresh parent selection when protected main advances during verification.

- Use the Nixpkgs-provided CLI without a separate upstream build graph, and refresh native modules and shared Nixpkgs through the existing weekly workflow, including both lockfiles in update PRs.

- Use the Nixpkgs-provided native Devenv CLI for non-flake local and hosted tasks, add an optional private SecretSpec Cachix prompt, and check named cache token permissions without uploading.

- Verify clean-store consumers through Cachix and its pinned official NixOS upstream, retaining substitution-only execution and recursive signature checks.

- Separate scan dependency fingerprints and retain fresh observations while reducing repeated inventory and advisory database work.

- Use a strictly tested signal-only decision relay and minimal native controller task profiles.

- Reconcile publication destinations before transfer and verify remote identities with backward-compatible receipt journals.

- Inspect scheduling and observation metadata before payload transfer, and reuse verified immutable packet bytes within a job while repeating authority checks.

- Bound optional CI transport and required evidence recovery, clean up nested processes, and reconcile exact-head merge queue state idempotently.

- Verify public cache identities before publication completes and exercise public bytes and signatures weekly in a disposable consumer store.

### Changed

- Add a default-enabled manual CI `reuse_builds` option. Disabling it omits only
  authenticated Actions artifact imports while retaining all selected validation,
  runtime builds, ordinary Nix caches and current admission checks.
- Reconcile only the latest successful qualification by default, with an explicit
  historical run input for recovery. Avoid duplicate active refreshes and active
  or completed publications for the same qualification run, attempt and purpose.
- Give read-only runtime prewarming its own concurrency group so it cannot hold
  the publication queue, and reuse resolved supply-protector paths during scans.
- Reuse authenticated exact CI build outputs across pull requests, the merge queue,
  and fresh main qualification, while preserving current tests, scans and release
  approval. Keep candidate builders separate from the job that signs receipts.
- Prepare one fresh verified vulnerability database per qualification or refresh
  run, with separate matcher probes and complete reports for every profile.
- Remove verified native-addon build metadata and the installed node-gyp build tool
  after compilation, keeping the compiled runtime addons and stock Node/OpenSSL.
- Export transient Nix closures with Zstandard and avoid recompressing their
  artifact uploads. Retain candidate caches for seven days.
- Default hosted runtime validation to two bounded build slots after a matched
  hosted pair completed 329 seconds (14.47%) faster with identical outputs for all
  19 targets. Preserve the serial dispatch option and serial native/preflight runs.

### Fixed

- Allow the native lock updater to prewarm its synchronized `flake.lock` and `devenv.lock` changes while rejecting runtime source edits and native-lock changes in release prewarm.

- Identify cache diagnostics with an explicit HTTP client user-agent and distinguish Cloudflare request blocks from rejected tokens.

- Require separate exact-product approval for rolling and release publication,
  compare canonical identities with strict schema types, and recheck live review
  before completing admission.

- Recognize the native ORAS missing-manifest diagnostic only for the exact public XO handoff reference, so publication can safely resume an absent OCI destination.

- Read the native multi-profile scans.json observation document with a dedicated 128 MiB bound while retaining 16 MiB limits for other packet metadata and all integrity/deadline checks.

- Read back all eight approved paths and NAR hashes from the protected public
  cache after upload, bypassing local metadata caches. Stop before publication
  checkpoints and downstream handoffs if remote bytes differ or are unavailable.
- Restore the protected XO public cache and signing key to isolated CI clients,
  without accepting inherited or candidate Nix configuration. Retain signature
  verification, sandboxed pure evaluation and disabled remote builders.
- Bound qualification artifact downloads to ten minutes, with a ten-second forced
  termination grace, before cleaning partial files and trying authenticated
  retained evidence. Preserve exact attempts, signatures and live admission.
- Report bounded attestation-verifier failure categories without exposing raw
  verifier output, request URLs, local paths or credentials. Preserve all signer,
  source and hosted-runner verification requirements.
- Confirm acknowledged journal checkpoints with bounded retries of only the
  known prior reference, preserving conflict detection and immutable recovery.
- Treat absent historical pull-request associations as unavailable build-cache
  candidates, while rejecting malformed provenance and retaining cold builds.
- Bind optional publication and refresh requests to an exact qualification
  attempt, and verify the downloaded native producer before using its evidence.
- Report bounded rate-limit metadata and fixed authority API failure categories
  without printing raw headers, response messages or credentials.
- Retry temporary GitHub authority read failures within three attempts and report
  bounded HTTP status diagnostics when publication or reconciliation is blocked.
- Report bounded registry error categories when private evidence uploads fail,
  without printing credentials, request URLs, or raw registry responses.
- Authenticate the unique GitHub merged event for decision provenance when a
  queued PR retains a stale merge-preview SHA; keep exact content, protected-main
  ancestry, and live human authority checks unchanged.

- Keep repeated private evidence uploads byte-identical by normalizing only the
  OCI transport timestamp, while preserving actual producer and scan timestamps.
- Recognize validated risk-identity hashes in security decision JSON without
  exempting neighboring credentials, other files, or deleted-secret history.
  Require human review of secret-scanner configuration changes.
- Authenticate complete four-profile decision ledgers up to a bounded 16 MiB
  using immutable Git object identity and the existing exact-commit human review.
- Run all repository contracts for repository-check definitions without rebuilding
  unchanged XO applications. Decision controller and ledger edits likewise run
  their native contracts without recompiling unchanged application outputs.

## [0.10.1] - 2026-10-19

### Security

- Require live human security admission for all four distributed profiles and
  approval of each exact release product before cache, tag, release, or handoff
  publication. Keep publication disabled until the approval path is activated.
- Inventory installed npm packages, native binaries, immutable sources and
  derivations, and shipped-file exposure. Preserve raw findings and reject
  incomplete inventories, unhealthy scanners, and stale vulnerability databases.
- Preserve reviewed runtime policy for profiles with no findings, so an empty
  vulnerability report cannot silently authorize expanded exposure.
- Preserve the verified XO Node/OpenSSL runtime and isolated file-restore helper
  integration, including checks of the active crypto library and refusal to
  fall back to privileged host parsing when an isolated backend fails.
- Run pinned CodeQL analysis for Actions, JavaScript/TypeScript, and Python on
  pull requests and merge groups.
- Use scoped organization Apps and short-lived queue credentials. Keep repository
  metadata reads separate from the read-only administration audit credential.

### Changed

- Update Nixpkgs to use its packaged OpenSSL 3.5.9 and Node 22.23.3. Remove
  the custom crypto rebuild; verify the stock runtime and mapped library paths.
- Separate immutable qualification from public distribution. Retain candidate
  Nix closures privately, restore exact approved outputs without builders, and
  publish digest-addressed handoffs for independent Maestro qualification.
- Resume interrupted publication through durable journals while preserving exact
  tags, output identities, and release bytes. Refresh scans without changing the
  original product identity or requiring approval of the same release again.
- Refresh the latest and rolling XO channels and libvhdi source pins while
  preserving the independently selected stable channel.
- Run cheap repository checks before runtime and supply tests, and keep rolling
  prewarming local until its product has passed publication admission.

### Fixed

- Retain plain runtime script and schema files in closure evidence while
  requiring exact derivation identities for shipped native code and npm roots.
- Preserve stronger severity, CVSS, and exploitation data from related scanner
  advisories when deciding whether a product needs new human security review.
- Validate normalized dependency mirrors offline and retry failed fetches in clean
  temporary caches without weakening archive hashes or integrity checks.
- Reconcile update approvals from protected default-branch code and validate
  exact proposal heads before queue entry.
- Preserve private evidence access and authenticated recovery after temporary
  Actions artifacts expire. Verify both original product and current scanner
  provenance when refreshing historical candidates.

## [0.10.0] - 2026-08-28

### Added

- Retain public immutable decision-byte reuse observations from hosted authority and publication jobs while keeping live authorization checks fresh. Suppress unsuccessful queue callbacks before controller startup.

- Prewarm the exact rolling candidate closure in the existing
  `xen-orchestra-ce` Cachix before preserving it in a draft pull request.
- Add `packages.x86_64-linux.automation-runtime`, a reusable closure containing
  the packaged CI, publication, trusted-queue, and updater applications.

### Changed

- Move live repository references to `closure-labs/xo-nixpkg`, require the
  repository merge queue, and make successfully prewarmed rolling candidates
  eligible for trusted auto-merge while retaining broken candidates as drafts.
- Remove the obsolete Forgejo updater and replace the retired updater GitHub
  App with narrowly scoped built-in workflow tokens; trusted queue automation
  approves and waits for GitHub's
  native approval-gated CI on bot-created pull requests before enrolling their
  exact head commit, using the normalized `github-actions` API login for author
  validation.
- Stream paginated Xen Orchestra commit discovery through files to avoid
  process argument limits, update only semantically changed channels, and
  limit pull-request validation and publication to those channel outputs.
- Preserve broken rolling candidates for diagnosis while failing their update
  run when realization or Cachix publication fails.
- Export one `lib.binaryCache` definition for the Cachix name, URL, and public
  key; use it for flake trust, supply assertions, publication, and prewarming.
- Keep the schema-v2 classifier and CI plans as the sole supported CI model.
  Remove the pre-1.0 schema-v1 `ciWorkflows`, `mkCiWorkflow`,
  `prepareCiWorkflow`, `evaluateCiWorkflowGate`, and `ciWorkflowSchemaVersion`
  library interfaces and the `prepare-ci` and `ci-gate` apps. Consumers should
  migrate to `lib.ciClassifier`, `lib.ciPlans`, `classify-ci`, `run-ci-plan`,
  `ci`, and `publish`.

### Fixed

- Require a repository-scoped `MERGE_QUEUE_TOKEN` before installing Nix, and
  diagnose missing Actions, Contents, or Pull requests write permission when
  workflow approval or exact-SHA merge-queue enrollment is denied.
- Retry transient update-branch pushes and pull-request mutations without
  weakening force-with-lease or retrying persistent policy rejections.
- Accept the flake's cache configuration during the initial shared Nix setup,
  allowing scheduled apps to substitute the published automation runtime.

## [0.9.5] - 2026-08-20

### Added

- Publish a reproducible supply assertion plus SPDX 2.3 and CycloneDX 1.5
  runtime-closure documents for every Xen Orchestra channel. The assertion
  retains the exact protected store closure and is distributed through the
  existing signed Cachix cache for downstream verification.

### Changed

- Establish the supply-protector output as a cryptographic dependency contract
  for downstream flakes. NiXOA Core can verify the immutable Xen Orchestra
  store identity, retained closure reference, Cachix trust root, and document
  hashes before linking the upstream SPDX document into its appliance
  attestation.

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
