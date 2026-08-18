#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if (( $# > 1 )); then
  echo 'usage: update-libvhdi.sh [GITHUB_OUTPUT]' >&2
  exit 2
fi

"${XO_NIXPKG_SOURCE_ROOT:-$PWD}/scripts/update-libvhdi.sh"
nix build --accept-flake-config --no-write-lock-file .#libvhdi -L
version=$(jq -er .pins.libvhdi.version npins/sources.json)

if (( $# == 1 )); then
  printf 'version=%s\n' "$version" >>"$1"
else
  printf 'version=%s\n' "$version"
fi
