#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${CACHIX_AUTH_TOKEN:?CACHIX_AUTH_TOKEN must be set}"

mapfile -t package_paths < <(
  nix build \
    --accept-flake-config \
    --no-write-lock-file \
    --no-link \
    --print-out-paths \
    .#xen-orchestra-ce \
    .#libvhdi
)

if [[ ${#package_paths[@]} -ne 2 ]]; then
  printf 'Expected two final package paths, found %s\n' "${#package_paths[@]}" >&2
  exit 1
fi

cachix push xen-orchestra-ce "${package_paths[@]}"
