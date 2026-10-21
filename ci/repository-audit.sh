#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# Keep the native task's daemon-compatible client when entering the packaged
# helper; its runtime PATH otherwise shadows installed Determinate with pkgs.nix.
nix_bin=${XO_NIXPKG_AUDIT_NIX_BIN:-nix}
if [[ $nix_bin != nix ]]; then
  [[ $nix_bin == /nix/*/bin/nix && -x $nix_bin ]]
fi
exec "$nix_bin" flake check --accept-flake-config --no-write-lock-file "$@"
