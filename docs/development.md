<!-- SPDX-License-Identifier: Apache-2.0 -->
# Development Guide

## Setup

XO uses Devenv's non-flake configuration: `devenv.yaml`, `devenv.lock`, and
`devenv.nix`. The repository flake exposes the Nixpkgs-provided Devenv CLI and the
small commands called by tasks; it does not define a Devenv flake shell.

```bash
git clone https://github.com/closure-labs/xo-nixpkg.git
cd xo-nixpkg
nix run --accept-flake-config .#devenv -- shell
nix run --accept-flake-config .#devenv -- test
```

The CLI follows the repository's Nixpkgs input, with no separate Devenv release
pin or upstream CLI build graph. Native modules use the CLI's default rolling
source. The existing weekly input workflow refreshes `devenv.lock` and the
Nixpkgs input in `flake.lock`, checks their shared Nixpkgs identity, and includes
both files in its update PR through the packaged updater command. The workflow
path, historical PR title and automatic queue guard stay unchanged; a PR that
changes both lockfiles needs normal source review. XO channel sources retain
their dedicated updaters.

With a compatible Devenv already installed, use `devenv shell` and `devenv test`.
`nix develop --accept-flake-config` remains a plain `mkShellNoCC` alternative.
The toolchain includes Node.js 22, Yarn classic, Valkey, native Node build
helpers, update tools, Nix linters, actionlint, ShellCheck, and zizmor.

The pinned runtime uses stock Nixpkgs Node 22.23.3 and OpenSSL 3.5.9. Both
substitute from the official Nix binary cache. `nix/runtime-node.nix` requires
the patched OpenSSL series without overriding its source or rebuilding Node;
the package install check verifies both the reported crypto version and the
actual mapped library paths.

### Public cache and optional local token prompt

Public development and CI pull from `https://xen-orchestra-ce.cachix.org` with
`xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E=`.
The shell exports the same trust root through `NIX_CONFIG` for nested commands.
No token is needed to enter the shell or run validation.

To test a Cachix token locally, create a token restricted to the
`xen-orchestra-ce` cache in Cachix, with write permission if you want the
read-only diagnostic to confirm that permission. Then:

```bash
cp devenv.local.yaml.example devenv.local.yaml
unset CACHIX_AUTH_TOKEN
nix run --accept-flake-config .#devenv -- shell
# Devenv prompts privately for CACHIX_XO_DEVENV_TOKEN when it is missing.
# Inside the shell:
devenv tasks run cache:doctor
```

The ignored override enables SecretSpec's `keyring` provider. An unlocked
system keyring and an interactive terminal are required; headless runners
should use environment-backed runtime credentials instead. Devenv stores its
built-in Cachix secret under project `devenv-cachix`, profile `default`, with
name `CACHIX_XO_DEVENV_TOKEN`. This differs from XO's project manifest and the
legacy publication credential `CACHIX_AUTH_TOKEN`. The local `development`
profile contains no credential declarations, including inherited defaults.
Never put the token value in YAML, Nix, a command argument, or a committed file.

`cache:doctor` reads Cachix metadata and prints only the expected cache identity,
signing-key match, and effective `Read`, `Write`, or `Admin` permission. It exits
successfully only for `Write` or `Admin`; public read access cannot prove token
validity. It never uploads, authorizes publication, or proves that public cache
bytes are available. Remove `devenv.local.yaml` to return to token-free startup.

Automatic `cachix.push` is not enabled: Devenv observes realized toolchain paths,
while this repository publishes only exact admitted products through separately
credentialed commands. Local token setup does not change those gates. The
explicit SecretSpec `runtime` and `github-*` profiles remain runtime contracts;
do not select them for Devenv's Nix evaluation.

See the upstream [binary cache guide](https://devenv.sh/binary-caching/) for the
native SecretSpec integration and [GitHub Actions guide](https://devenv.sh/integrations/github-actions/)
for running commands on ordinary hosted runners.

```bash
valkey-server --bind 127.0.0.1
```

The XO updater enters the pure `.#updater` shell automatically when needed.

CI output reuse, scanner database sharing, compression measurements and the
bounded concurrency pilot are documented in [Build performance](ci-build-performance.md).

## Build and Evaluate

```bash
# Build the default/latest XO package, or an explicit channel
nix build .#xen-orchestra-ce
nix build .#stable
nix build .#rolling
nix build .#supply-protector-latest

# Validate the in-repository FUSE3 libvhdi package
nix eval --raw .#packages.x86_64-linux.libvhdi.name
nix eval --raw .#packages.x86_64-linux.libvhdi.fuseBackend
nix build --no-link .#libvhdi

# Execute the full repository pipeline used by CI
nix run .#ci

# Pure CI-style evaluation
nix eval --accept-flake-config --json .#checks.x86_64-linux --apply builtins.attrNames
```

## CI preflight and trusted prewarming

`nix run .#ci` evaluates the complete flake, then runs all selected cheap
contracts before selected runtime, VM, linkage and supply checks. The classifier
contract declares `preflightTargets`; each selected target runs once. A failed
preflight emits its evidence and stops the runtime stage. Selection and required
CI verdicts retain their existing behavior.

Validation and publication retain schema-v2 manifests plus separate schema-v1
per-target timing receipts. Set `XO_NIXPKG_CI_EVIDENCE` for an explicit directory;
the default is `$RUNNER_TEMP/xo-nixpkg-ci-evidence` in Actions and
`${TMPDIR:-/tmp}/xo-nixpkg-ci-evidence` locally. Each invocation clears its own
previous receipts. CI uploads evidence after success or failure. Timing includes
Nix startup, realization and substitution; it does not isolate compilation.

Official-release and flake-lock automation prewarm changed package/supply roots
and the stock cached runtime respectively before opening update PRs. A failed prewarm
preserves a draft PR and fails the updater. The manual **Prewarm protected
runtime** workflow can realize the current protected-main runtime locally without changing
pins or publishing a release. Its packaged app is `.#prewarm-runtime`; official
release automation calls `.#prewarm-release-candidate -- latest,stable` with only
the channels actually changed.

Hosted prewarming requires the protected default branch at the exact event SHA,
a schedule or manual event, and only the declared updater pin changes. It checks
GitHub's current branch identity and protection before realizing candidates.
Candidate realization has no cache write credential. Public cache publication
occurs only after live security admission in the publication controller.

Review approvals first trigger an observer with no checkout or credentials.
Privileged queue reconciliation runs from default-branch-owned workflow code and
checks out the default branch; it then revalidates candidate identity, approval,
paths and current SHA. The observer event carries no authority to merge by itself.
See [pilot measurements](ci-pilot-benchmarks-2026-10-14.md) for validation and
performance limits.

## Updating xen-orchestra-ce

Use the release updater to refresh both official package outputs. Discovery
searches commits that changed upstream's root `CHANGELOG.md`, accepts only
unscoped `feat: release VERSION` markers, assigns the newest match to `latest`,
and assigns the newest non-excluded predecessor to `stable`. Known-bad stable
candidates are recorded in `excludedStableVersions` in the XO source lock;
currently `6.8` is excluded. Scoped `feat(lite):` commits and XO Lite tags belong
to a separate upstream product and are ignored.

```bash
nix run .#update-xo-release

# Validate after update
nix run .#ci
```

The script atomically updates only the affected channel entries in
`nix/sources/xen-orchestra.json`, their matching immutable flake inputs, and
their lock nodes. Existing Yarn dependency hashes are reused when their lock
files did not change. Commit discovery streams paginated GitHub responses
through temporary files, so long upstream histories cannot exceed the process
argument limit. CI recognizes this generated pin/flake/lock cohort and builds
only the changed channels.

Each newly detected release gets a version-specific pull request with a review
request. An approval on the current head commit from a maintainer with write,
maintain, or admin repository permission is required before trusted automation
enrolls it in the merge queue. After the gated merge, automation creates only
the immutable XO package tag; legacy `latest` and `stable` Git tags are not moved.

To refresh `rolling` to upstream HEAD for troubleshooting, run:

```bash
nix run .#update-xo-rolling
```

This realizes the exact `rolling-candidate` closure and uploads it to the
existing `xen-orchestra-ce` Cachix before opening a draft pull request. A
realization or upload failure still opens the draft, records it as broken, and
fails the automation run so the candidate remains diagnosable. Pull-request CI
then starts from a clean runner and substitutes the prewarmed closure. The
`update-xo-upstream` app remains as a compatibility alias.

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

## Syncing with Maestro

When syncing package changes with Maestro:

```bash
# In the Maestro repository
git log --oneline pkgs/xen-orchestra-ce/

# Compare package definitions
diff -u /path/to/maestro/pkgs/xen-orchestra-ce/default.nix \
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

Qualification builds and scans exact immutable XO, supply and libvhdi outputs
without publication credentials. A separate controller runs only after the
qualification workflow has completed successfully. It authenticates the signed
evidence, checks live policy and human security decisions, restores the retained
NAR transport without builders, and pushes only the admitted store paths.
A project release additionally requires an independent approval of the complete
product identity; publication never treats a generated receipt as authority.

Project and upstream package tags remain independent and immutable. The project
tag comes from `VERSION` and its GitHub Release uses that tag's matching
changelog section. Upstream package tags normalize two-component versions
(`6.8` becomes `v6.8.0`); they do not create GitHub Release objects. The XO
`latest`, `stable`, and `rolling` names remain flake package outputs.

Protected-main publication retains pending requests in its FIFO group and
rechecks live admission before each cache, tag or release side effect. Private
review packets retain the complete candidate evidence and transport for delayed
approval and recovery. Public downstream handoff packets are independently
signed and bind the exact channel, source revision, store path and NAR hash.
Each channel's `supply-protector` output retains its package closure and
SPDX, CycloneDX, closure graph, checksums and assertion files.

## Organization merge queue

The public `closure-labs/xo-nixpkg` repository requires GitHub's merge queue.
Pull requests and synthetic merge groups must pass `CI gate`, and review
conversations must be resolved. Successful rolling candidates are created ready
for the trusted automation queue without human approval; versioned release
candidates require an exact-head maintainer approval. Failed rolling prewarming
leaves the candidate draft for diagnosis. Protected-main publication retains
every pending request in its FIFO concurrency group and requires fresh live
admission of the exact signed product.

Update pull requests use job-scoped built-in GitHub tokens. Queue reconciliation
mints a short-lived repository-scoped token from the Decider App with Actions,
Contents and Pull requests write permissions; `DECIDER_CLIENT` is a repository
variable and `DECIDER_KEY` is a runtime secret. The separate read-only audit App
uses the `SECAUDIT_CLIENTID` variable and `SECAUDIT_PEM` secret, with its token
passed as `REPOSITORY_READ_TOKEN`. Approval authority is revalidated against
current human maintain/admin access and exact decision heads.

Cache publication, project tags and releases require fresh admitted evidence
and live policy checks. Release approval binds the complete immutable product
identity independently of security acceptance. Runtime credentials never enter
Nix evaluation or derivations. The cache name, URL and key remain flake data.

## Security inventory review

Run `nix run .#security-scan -- latest` to review one immutable channel. `stable`
and `rolling` are also supported; `CHANNEL` supplies the default when there is
no argument. The app realizes only that channel's supply protector, verifies
its checksums, asserted package/source/channel and CycloneDX bindings, and scans
with a fresh age-validated Grype database. Native and npm canaries must both
match before the actual scan proceeds. No write credential is needed.

Reports default to `security-report/<channel>`, with `SECURITY_OUTPUT` available
for an explicit destination. `raw.grype.json` preserves original matches;
`findings.json` binds normalized matches to immutable component identities;
`context.json` describes a **package** profile, not a consuming NixOS host.
`critical-applicability.json` contains classifications and exact dispositions,
plus inventory/rules/evaluator digests. `unresolved-critical.json` and
`summary.json` expose unresolved critical counts. Native components without
curated source/patch evidence remain unresolved rather than disappearing.

The main-only daily and manual workflow reviews latest, stable and rolling
independently, retaining reports after failures. It adds no required PR scan.
Cheap evaluator, normalization and scan fixtures run in ordinary CI when their
sources or rules change. `SECURITY_MODE=report` is the default: unresolved
findings do not fail it, while scanner/database, identity and malformed evidence
errors do. `SECURITY_MODE=enforce` fails on unresolved critical findings; keep
production reporting until the existing remediation and deployment acceptance
gates have passed.

`nix run .#security-applicability -- --help` exposes the standalone evaluator.
Its package also exposes `security-applicability.source` for consumers to bind
the exact shared Python implementation. Rules in
`nix/security-applicability-rules.json` start empty. A reviewed decision requires
an exact advisory/component/source binding, actual code hashes and applicable
runtime guards, with an owner, evidence and an expiry of at most 30 days. Changed,
missing or expired evidence yields unresolved findings. Manifest hashes alone,
NixOS, private networks and missing process observations are insufficient
evidence. The five reviewed npm findings remain unresolved: immutable built-in
callers suggest narrow future Handlebars guards, but dynamic plugin/config
exposure must first be established. See
[the npm triage](security-triage-2026-10-14.md).

Workflow command bodies use declared `devenv tasks` backed by flake-packaged leaf
commands. The existing pinned Determinate Nix setup runs on ephemeral GitHub
hosted runners. `nix run .#devenv -- tasks run --mode single --option
'packages:pkgs!' '' <task>` bootstraps the Nixpkgs-provided CLI and evaluates the
non-flake configuration with the minimal controller profile. Ordinary validation
uses public caches and needs no Cachix token, local override, or interactive
prompt. The committed configuration disables implicit SecretSpec resolution.
Only protected authority/publication steps receive their declared, scoped runtime
credentials. Keep them out of Devenv evaluation and derivations; adding a local
token or using the upstream integration does not enable automatic publication.
