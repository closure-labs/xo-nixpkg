# XO-only FUSE 2 compatibility

Upstream Xen Orchestra's `@vates/fuse-vhd` still imports `fuse-native` 2.2.6:
- [XO upstream dependency](https://github.com/vatesfr/xen-orchestra/blob/a50776cb7d013b359a34d9b0103665d158db1f0a/@vates/fuse-vhd/package.json)
- [Native addon API](https://github.com/fuse-friends/fuse-native/blob/v2.2.6/fuse-native.c)

The addon defines `FUSE_USE_VERSION 29` and uses the FUSE 2 `fuse_chan`,
`fuse_mount` and `fuse_new` API. It cannot become FUSE 3 compatible by changing an
include directory or library alias. Removing downstream system-library wiring
would instead use the npm package's bundled FUSE 2, not migrate upstream.

This leaf specializes the FUSE 2 branch of the final pinned Nixpkgs expression
at `3ec636362e1816bc2f0888fa0fa2c69f1bc9e504`, preserving its source and patch hashes:
- `pkgs/os-specific/linux/fuse/default.nix`: libfuse 2.9.9 source pin
- `pkgs/os-specific/linux/fuse/common.nix`: build, split outputs and wrapper policy
- `fuse2-Do-not-set-FUSERMOUNT_DIR.patch`, `fuse2-gettext-0.25.patch`: unchanged copies
- Conditional AArch64/LoongArch64 and glibc closefrom patches: original pinned fetches

The original Nixpkgs expression's MIT license is retained in `COPYING`.
Only XO's `mkXo` call receives this dependency. There is no overlay, global
`pkgs.fuse` replacement, bundled npm binary, or FUSE 3-to-2 ABI alias. Libvhdi
continues using modern `pkgs.fuse3`. We retain source rebuilds and installed
addon-load/ABI checks, plus a header/API compile check for this leaf. No setuid
wrapper or host configuration is installed by this change.

## Maintenance obligation and removal

FUSE 2 is **end-of-life**, unmaintained upstream since 2019, and removed from
current Nixpkgs. A pinned source is reproducible, not a security guarantee.
This repository now owns reviewing advisories and required backports for the
compatibility dependency; neither inherited Nixpkgs maintainers nor upstream
promise maintenance. Existing security inventory/admission gates still cover
it. Do not allowlist findings just to retain compatibility.

Remove this leaf and the FUSE 2-only addon wiring together when XO adopts a
maintained FUSE 3 binding. Validate mount/read/unmount and isolated file restore,
not just compilation, before switching ABIs. Existing tarball mode normalization
must remain while the upstream lock still includes those bundled tarballs.

Validation before merging: evaluate both current main and the nixpkgs-refresh
lock, build all XO channels, run installed addon/ABI checks and the XO service
and file-restore tests. Header compilation alone is not end-to-end validation.
