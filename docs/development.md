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
request. A human approval is required before trusted automation enrolls it in
the merge queue. After the gated merge, the immutable XO package tag is created
and the moving `latest` and `stable` Git tags are updated to their corresponding
immutable package-tag commits.

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
for the trusted automation queue; failed prewarming leaves the candidate draft
for diagnosis. Protected-main publication retains every pending run in its
FIFO concurrency group and can reuse successful ancestral merge-group
validation.

Update pull requests and releases use job-scoped built-in GitHub tokens. The
trusted queue is the exception: approving action-required workflow runs and
enrolling an exact pull-request SHA requires the repository secret
`MERGE_QUEUE_TOKEN`. It must be a fine-grained PAT restricted to
`closure-labs/xo-nixpkg`, owned by an authorized automation identity, with
Actions, Contents, and Pull requests read/write permissions. The workflow
fails before checkout and Nix setup if that secret is absent; it never falls
back to `github.token`.

The release environment, `MERGE_QUEUE_TOKEN`, and `CACHIX_AUTH_TOKEN` remain
repository-scoped; recheck their availability after any transfer or visibility
change and rotate the PAT before its configured expiration. The cache name,
URL, and public key are flake data exposed through `lib.binaryCache`, so there
is no `CACHIX_CACHE_NAME` secret.
