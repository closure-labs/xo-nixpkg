<!-- SPDX-License-Identifier: Apache-2.0 -->
# Testing Guide

## Local Checks

```bash
# Evaluate all outputs (no builds)
nix flake check --all-systems --no-build

# Build the XO package
nix build .#xen-orchestra-ce

# Validate the pinned libvhdi package resolves through the published cache
nix eval --raw .#packages.x86_64-linux.libvhdi.name
nix eval --raw .#packages.x86_64-linux.libvhdi.fuseBackend
nix build --no-link --max-jobs 0 .#libvhdi \
  --option extra-substituters 'https://libvhdi-nixpkg.cachix.org' \
  --option extra-trusted-public-keys 'libvhdi-nixpkg.cachix.org-1:HvYHKZcfczn2nGfCmd7F21E/MDZrlaXtN3p9mWAZT/4='
```

## Runtime Smoke Tests

### xen-orchestra-ce

```bash
nix build .#xen-orchestra-ce
./result/bin/xo-server --help
./result/bin/xo-server --version || true
```

### libvhdi

```bash
nix eval --raw .#packages.x86_64-linux.libvhdi.name
nix eval --raw .#packages.x86_64-linux.libvhdi.fuseBackend
nix build --no-link --max-jobs 0 .#libvhdi \
  --option extra-substituters 'https://libvhdi-nixpkg.cachix.org' \
  --option extra-trusted-public-keys 'libvhdi-nixpkg.cachix.org-1:HvYHKZcfczn2nGfCmd7F21E/MDZrlaXtN3p9mWAZT/4='
```

## Submission-Oriented Checks

Before opening nixpkgs PRs:

```bash
# Evaluate current flake
nix flake check --all-systems --no-build

# Optional: dry-run package build planning
nix build .#xen-orchestra-ce --dry-run
nix build --no-link --max-jobs 0 .#libvhdi \
  --option extra-substituters 'https://libvhdi-nixpkg.cachix.org' \
  --option extra-trusted-public-keys 'libvhdi-nixpkg.cachix.org-1:HvYHKZcfczn2nGfCmd7F21E/MDZrlaXtN3p9mWAZT/4='
```

## Common Failures

### Yarn Hash Mismatch

If `yarnOfflineCache` hash mismatches:

```bash
./scripts/update.sh --release
```

### Source Hash Mismatch

If `src.hash` mismatches for xen-orchestra-ce:

```bash
nix-prefetch-github vatesfr xen-orchestra --rev <commit-sha>
```

### Broken Symlinks in Output

The package currently removes broken symlinks during `preFixup`:

```nix
preFixup = ''
  find "$out/libexec/xen-orchestra" -xtype l -delete || true
'';
```

## CI Coverage

CI currently checks:
- package builds for `xen-orchestra-ce`
- evaluation and cache substitution for the pinned `libvhdi` input
- `nix flake check`
- basic binary execution smoke tests
