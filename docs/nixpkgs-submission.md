<!-- SPDX-License-Identifier: Apache-2.0 -->
# Nixpkgs Submission Guide

This guide covers submission prep for packages tracked from this repository.

## Current Scope

- `xen-orchestra-ce`: maintained in this repo (`default.nix`)
- `libvhdi`: maintained in this repo at `nix/libvhdi.nix` from a locked official release asset.

## Upstream FUSE compatibility blocker

XO currently needs the private [FUSE 2 compatibility leaf](../nix/fuse2-compat/README.md)
for its upstream `fuse-native` dependency. Its packaging follows the former
Nixpkgs expression, but FUSE 2 is end-of-life and was removed from Nixpkgs;
this local compatibility exception does not imply eligibility for upstream
submission. Resolve the upstream binding migration or agree an explicit
maintenance approach before proposing XO to Nixpkgs. Libvhdi remains on FUSE 3.

## Prerequisites

1. Package evaluates/builds locally:
```bash
nix flake check --all-systems --no-build
nix build .#xen-orchestra-ce
```

2. Source and yarn hashes are current:
```bash
./scripts/update.sh --release
```

3. Metadata is ready for review:
- `meta.description`, `meta.license`, `meta.platforms`, `meta.mainProgram`
- `meta.maintainers` should be finalized before PR submission

## xen-orchestra-ce Submission Steps

### Step 1: Prepare nixpkgs Checkout

```bash
git clone https://github.com/YOUR-USERNAME/nixpkgs.git
cd nixpkgs
git remote add upstream https://github.com/NixOS/nixpkgs.git
```

### Step 2: Create Package Directory

```bash
mkdir -p pkgs/by-name/xe/xen-orchestra-ce
```

### Step 3: Port the complete package expression

Copying `default.nix` alone is insufficient: it imports sibling files and expects
repository-specific arguments. This is a porting checklist, not a ready-to-submit
Nixpkgs expression. In the new package directory:

- Port `default.nix` to `package.nix`, preserving or adapting
  `nix/runtime-node.nix` and `nix/yarn-platform-tools.nix` and their relative imports.
- Replace the injected `source` with a fixed-output source fetcher. Bind
  `sourceRev`, `version`, `yarnHash` and `docsYarnHash` to the selected immutable
  channel entry in `nix/sources/xen-orchestra.json`; `channel` is an explicit
  repository argument, not an automatic Nixpkgs dependency.
- Resolve the explicit `fuse2` dependency. The local `nix/fuse2-compat` directory
  includes the compatibility expression and supporting files; copying only XO's
  expression will not provide it. FUSE 2's EOL status is an upstream acceptance
  and maintenance concern requiring discussion, not evidence of a categorical
  Nixpkgs ban. Do not replace libvhdi's FUSE 3 dependency.
- Verify every remaining `callPackage` argument against the target Nixpkgs
  revision; repository channel/source inputs are not supplied automatically.
- Start with the repository's exercised `x86_64-linux` target. Broader platform
  claims require builds and runtime validation on those platforms.

Do not submit the repository's automation credentials, private evidence registry,
release controller or Cachix write setup as package build dependencies. They are
not required to build the ordinary package from public sources.

### Step 4: Finalize Maintainers

- Add yourself to `maintainers/maintainer-list.nix` (if needed)
- Set `meta.maintainers` in `package.nix` to your maintainer entry

### Step 5: Test in nixpkgs

```bash
nix-build -A xen-orchestra-ce
nixpkgs-review wip
```

### Step 6: Commit and Open PR

```bash
git checkout -b xen-orchestra-ce-init
git add pkgs/by-name/xe/xen-orchestra-ce
git add maintainers/maintainer-list.nix  # if changed
git commit -m "xen-orchestra-ce: init"
git push origin xen-orchestra-ce-init
```

## libvhdi Submission Notes

If `libvhdi` is not yet in nixpkgs, prepare it from `nix/libvhdi.nix` and
replace the injected `source` argument with the corresponding nixpkgs
`fetchurl` expression. Keep FUSE3 as its sole FUSE dependency.

## References

- [Nixpkgs Contributing Guide](https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md)
- [pkgs/by-name README](https://github.com/NixOS/nixpkgs/blob/master/pkgs/by-name/README.md)
