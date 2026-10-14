<!-- SPDX-License-Identifier: Apache-2.0 -->
# Development Guide

## Setup

```bash
git clone https://github.com/closure-labs/xo-nixpkg.git
cd xo-nixpkg
nix develop --accept-flake-config
```

The plain `mkShellNoCC` toolchain includes Node.js 22, Yarn classic, Valkey,
native Node build helpers, update tools, Nix linters, actionlint, ShellCheck,
and zizmor. Evaluation is pure.

The repository also exposes the same toolchain as a Devenv environment:

```bash
devenv shell
devenv test
```

Devenv's Cachix integration pulls from `https://xen-orchestra-ce.cachix.org`
with the public key
`xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E=`.
The shell also exports both values through `NIX_CONFIG`, so nested `nix`
commands use the pinned trust root. The cache stays read-only unless a
developer explicitly configures a local `cachix.push` value.

```bash
valkey-server --bind 127.0.0.1
```

The XO updater enters the pure `.#updater` shell automatically when needed.

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

After validation and selected Cachix publication succeed, the gated job
maintains two independent tag streams. It creates the immutable project tag
from `VERSION` and idempotently publishes that tag as a GitHub Release using
only the tagged commit's matching changelog section. When the push changes the
`latest` XO version or revision, it also creates an immutable lightweight XO
package tag on that downstream pin commit; two-component upstream versions are
normalized (`6.8` becomes `v6.8.0`) and three-component versions are retained
(`6.8.1` becomes `v6.8.1`). Existing tags are never moved, and XO package tags
do not create GitHub Release objects. The XO `latest`, `stable`, and `rolling`
names remain non-tagged flake package outputs.

Protected-main publication runs in a FIFO concurrency group and retains every
pending run. Validation and Cachix publication share one runner and Nix store;
a successful merge-group run can satisfy validation for an ancestral main SHA,
while only the path delta after that SHA is revalidated. Missing workflow-run
history, API failures, incomplete Git history, and non-ancestral SHAs all fall
back to the complete validation plan.

The same publication plan pushes each channel's `supply-protector` store output.
Those outputs retain the exact XO closure and package deterministic SPDX,
CycloneDX, closure-graph, checksum, and assertion files for downstream flakes.

## Organization merge queue

The public `closure-labs/xo-nixpkg` repository requires GitHub's merge queue.
Pull requests and synthetic merge groups must pass `CI gate`, and review
conversations must be resolved. Successful rolling candidates are created ready
for the trusted automation queue without human approval; versioned release
candidates require an exact-head maintainer approval. Failed rolling prewarming
leaves the candidate draft for diagnosis. Protected-main publication retains
every pending run in its FIFO concurrency group and can reuse successful
ancestral merge-group validation.

Update pull requests and releases use job-scoped built-in GitHub tokens. The
trusted queue is the exception: approving action-required workflow runs and
enrolling an exact pull-request SHA requires the repository secret
`MERGE_QUEUE_TOKEN`. It must be a fine-grained PAT restricted to
`closure-labs/xo-nixpkg`, owned by an authorized automation identity, with
Actions, Contents, and Pull requests read/write permissions. The workflow
fails before checkout and Nix setup if that secret is absent; it never falls
back to `github.token`. Reconciliation runs after updater or CI completion,
after an approval is submitted, on demand, and on a daily repair schedule. It
does not wait inside a runner: pending, newly authorized, failed, and
awaiting-review candidates are reported as state, while identity, changed-file,
credential, and API failures fail the reconciliation job.

The release environment, `MERGE_QUEUE_TOKEN`, and `CACHIX_AUTH_TOKEN` remain
repository-scoped; recheck their availability after any transfer or visibility
change and rotate the PAT before its configured expiration. The cache name,
URL, and public key are flake data exposed through `lib.binaryCache`, so there
is no `CACHIX_CACHE_NAME` secret.

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
