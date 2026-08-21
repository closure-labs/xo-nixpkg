<!-- SPDX-License-Identifier: Apache-2.0 -->
# Development Guide

## Setup

```bash
git clone https://github.com/declarative-dale/xo-nixpkg.git
cd xo-nixpkg
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
and assigns the next match to `stable`. Scoped `feat(lite):` commits and XO
Lite tags belong to a separate upstream product and are ignored.

```bash
nix run .#update-xo-release

# Validate after update
nix run .#ci
```

The script atomically updates `nix/sources/xen-orchestra.json` and the matching
immutable flake inputs. Existing Yarn dependency hashes are reused when their
lock files did not change. Scheduled discovery opens or refreshes a standing
candidate pull request; the ordinary pull-request workflow is responsible for
building every affected package output.

To refresh `rolling` to upstream HEAD for troubleshooting, run:

```bash
nix run .#update-xo-rolling
```

This refreshes a separate rolling candidate pull request. A deterministic
upstream build failure remains visible on that pull request instead of being
retried every day; the next upstream revision replaces the candidate. The
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

After the gated main build succeeds, automation creates only the immutable
project tag. The same gated job idempotently publishes that semantic-version
tag as a GitHub Release using only the tagged commit's matching changelog
section. Re-running the workflow never rewrites an existing tag or duplicates
a published release. The XO `latest`, `stable`, and `rolling` names are flake
package outputs and are unrelated to project-release tags.

Protected-main publication runs in a FIFO concurrency group and retains every
pending run. Validation and Cachix publication share one runner and Nix store;
a successful merge-group run can satisfy validation for an ancestral main SHA,
while only the path delta after that SHA is revalidated. Missing workflow-run
history, API failures, incomplete Git history, and non-ancestral SHAs all fall
back to the complete validation plan.

The same publication plan pushes each channel's `supply-protector` store output.
Those outputs retain the exact XO closure and package deterministic SPDX,
CycloneDX, closure-graph, checksum, and assertion files for downstream flakes.

## Public organization migration

The workflow already listens for `merge_group`, but a personal repository
cannot enable GitHub's merge queue. After transferring the still-public
repository to the organization:

1. Install the update GitHub App on the organization repository and verify the
   release environment, App variables/secrets, Cachix token, and automation
   token remain available.
2. Replace the strict "up to date before merging" policy with "require merge
   queue", retaining `CI gate` as the required status and conversation
   resolution as required.
3. Queue a documentation-only PR and a package-changing PR. Confirm both get a
   `merge_group` gate and that the resulting main run reuses the successful
   ancestral merge-group validation.
4. Keep standard GitHub-hosted runners; they remain free while the repository
   is public. Revisit runner and environment policy only if visibility changes.
