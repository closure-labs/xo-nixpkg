<!-- SPDX-License-Identifier: Apache-2.0 -->
# Testing Guide

## Local Checks

```bash
# Evaluate all outputs (no builds)
nix flake check --all-systems --no-build

# Build each package
nix build .#xen-orchestra-ce
nix build .#libvhdi
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
nix build .#libvhdi
./result/bin/vhdiinfo -V
./result/bin/vhdimount -V
```

## Submission-Oriented Checks

Before opening nixpkgs PRs:

```bash
# Evaluate current flake
nix flake check --all-systems --no-build

# Optional: dry-run package build planning
nix build .#xen-orchestra-ce --dry-run
nix build .#libvhdi --dry-run
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
- package builds for `xen-orchestra-ce` and `libvhdi`
- `nix flake check`
- basic binary execution smoke tests
