<!-- SPDX-License-Identifier: Apache-2.0 -->
# Nixpkgs Submission Guide

This guide covers submission prep for packages tracked from this repository.

## Current Scope

- `xen-orchestra-ce`: maintained in this repo (`default.nix`)
- `libvhdi`: consumed as a pinned release-tag flake input from `declarative-dale/libvhdi-nixpkg`; submit from that source tree or vendor its package definition into your nixpkgs branch.

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

### Step 3: Copy Package Files

```bash
cp /path/to/xen-orchestra-ce-nix/default.nix pkgs/by-name/xe/xen-orchestra-ce/package.nix
```

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

If `libvhdi` is not yet in nixpkgs, prepare it from the
`declarative-dale/libvhdi-nixpkg` package definition and submit as a separate
package PR (or separate commit in the same PR if maintainers prefer bundling).

## References

- [Nixpkgs Contributing Guide](https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md)
- [pkgs/by-name README](https://github.com/NixOS/nixpkgs/blob/master/pkgs/by-name/README.md)
