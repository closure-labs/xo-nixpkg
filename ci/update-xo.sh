#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

mode=${1:?usage: update-xo.sh --release|--rolling [GITHUB_OUTPUT]}
shift
case "$mode" in
  --release | --rolling | --upstream) ;;
  *) echo "Unsupported update mode: $mode" >&2; exit 2 ;;
esac
if (( $# > 1 )); then
  echo 'usage: update-xo.sh --release|--rolling [GITHUB_OUTPUT]' >&2
  exit 2
fi

pin_file=${XO_NIXPKG_XO_PIN_FILE:-${XO_NIXPKG_SOURCE_ROOT:-$PWD}/nix/sources/xen-orchestra.json}
flake_file=${XO_NIXPKG_FLAKE_FILE:-${XO_NIXPKG_SOURCE_ROOT:-$PWD}/flake.nix}
before=$(sha256sum "$pin_file" "$flake_file")
if [[ -n ${XO_NIXPKG_UPDATE_XO_SOURCE_COMMAND:-} ]]; then
  bash "$XO_NIXPKG_UPDATE_XO_SOURCE_COMMAND" "$mode"
else
  bash "${XO_NIXPKG_SOURCE_ROOT:-$PWD}/scripts/update.sh" "$mode"
fi
after=$(sha256sum "$pin_file" "$flake_file")
changed=false
if [[ $before != "$after" ]]; then
  changed=true
  nix flake lock --accept-flake-config
  nix flake check --accept-flake-config --no-build --no-write-lock-file
fi

channel=latest
[[ $mode == --release ]] || channel=rolling
version=$(jq -er ".channels.$channel.version" "$pin_file")
rev=$(jq -er ".channels.$channel.rev" "$pin_file")
[[ $version =~ ^([0-9]+(\.[0-9]+)+|unstable-[0-9]{4}-[0-9]{2}-[0-9]{2})$ ]]
[[ $rev =~ ^[a-f0-9]{40}$ ]]

if (( $# == 1 )); then
  printf 'changed=%s\nversion=%s\nrev=%s\n' "$changed" "$version" "$rev" >>"$1"
else
  printf 'changed=%s\nversion=%s\nrev=%s\n' "$changed" "$version" "$rev"
fi
