#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

mode=${1:?usage: update-xo.sh --release|--upstream [GITHUB_OUTPUT]}
shift
case "$mode" in
  --release | --upstream) ;;
  *) echo "Unsupported update mode: $mode" >&2; exit 2 ;;
esac
if (( $# > 1 )); then
  echo 'usage: update-xo.sh --release|--upstream [GITHUB_OUTPUT]' >&2
  exit 2
fi

pin_file=${XO_NIXPKG_XO_PIN_FILE:-${XO_NIXPKG_SOURCE_ROOT:-$PWD}/nix/sources/xen-orchestra.json}
before=$(sha256sum "$pin_file" | cut -d ' ' -f 1)
bash "${XO_NIXPKG_SOURCE_ROOT:-$PWD}/scripts/update.sh" "$mode"
after=$(sha256sum "$pin_file" | cut -d ' ' -f 1)
changed=false
if [[ $before != "$after" ]]; then
  changed=true
  nix build --accept-flake-config --no-write-lock-file .#xen-orchestra-ce -L
fi

version=$(nix eval --accept-flake-config --raw .#xen-orchestra-ce.version)
rev=$(nix eval --accept-flake-config --raw .#xen-orchestra-ce.src.rev)
[[ $version =~ ^[0-9]+(\.[0-9]+)+$ ]]
[[ $rev =~ ^[a-f0-9]{40}$ ]]

if (( $# == 1 )); then
  printf 'changed=%s\nversion=%s\nrev=%s\n' "$changed" "$version" "$rev" >>"$1"
else
  printf 'changed=%s\nversion=%s\nrev=%s\n' "$changed" "$version" "$rev"
fi
