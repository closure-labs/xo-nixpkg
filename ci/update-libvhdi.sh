#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if (( $# > 1 )); then
  echo 'usage: update-libvhdi.sh [GITHUB_OUTPUT]' >&2
  exit 2
fi

pin_file=${LIBVHDI_PIN_FILE:-${XO_NIXPKG_SOURCE_ROOT:-$PWD}/nix/sources/libvhdi.json}
before=$(sha256sum "$pin_file" | cut -d ' ' -f 1)
bash "${XO_NIXPKG_SOURCE_ROOT:-$PWD}/scripts/update-libvhdi.sh"
after=$(sha256sum "$pin_file" | cut -d ' ' -f 1)
changed=false
if [[ $before != "$after" ]]; then
  changed=true
  nix build --accept-flake-config --no-write-lock-file .#libvhdi -L
fi
version=$(jq -er .version "$pin_file")

if (( $# == 1 )); then
  printf 'changed=%s\nversion=%s\n' "$changed" "$version" >>"$1"
else
  printf 'changed=%s\nversion=%s\n' "$changed" "$version"
fi
