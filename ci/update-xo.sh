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
before_pin=$(mktemp)
trap 'rm -f -- "$before_pin"' EXIT
cp "$pin_file" "$before_pin"
before_flake=$(sha256sum "$flake_file")
if [[ -n ${XO_NIXPKG_UPDATE_XO_SOURCE_COMMAND:-} ]]; then
  bash "$XO_NIXPKG_UPDATE_XO_SOURCE_COMMAND" "$mode"
else
  bash "${XO_NIXPKG_SOURCE_ROOT:-$PWD}/scripts/update.sh" "$mode"
fi
changed_channels_json=$(jq -cs '
  .[0] as $before | .[1] as $after |
  ["latest", "stable", "rolling"] |
  map(select($before.channels[.] != $after.channels[.]))
' "$before_pin" "$pin_file")
changed_channels=$(jq -r 'join(",")' <<<"$changed_channels_json")
changed=false
if [[ $(jq -r length <<<"$changed_channels_json") != 0 ]]; then
  changed=true
  lock_args=()
  while IFS= read -r channel; do
    lock_args+=(--update-input "xo-$channel")
  done < <(jq -r '.[]' <<<"$changed_channels_json")
  nix flake lock --accept-flake-config "${lock_args[@]}"
  nix flake check --accept-flake-config --no-build --no-write-lock-file
elif [[ $before_flake != "$(sha256sum "$flake_file")" ]]; then
  echo 'XO updater changed flake.nix without changing a channel pin' >&2
  exit 1
fi

channel=latest
[[ $mode == --release ]] || channel=rolling
version=$(jq -er ".channels.$channel.version" "$pin_file")
rev=$(jq -er ".channels.$channel.rev" "$pin_file")
stable_version=$(jq -er '.channels.stable.version' "$pin_file")
stable_rev=$(jq -er '.channels.stable.rev' "$pin_file")
[[ $version =~ ^([0-9]+(\.[0-9]+)+|unstable-[0-9]{4}-[0-9]{2}-[0-9]{2})$ ]]
[[ $rev =~ ^[a-f0-9]{40}$ ]]
[[ $stable_version =~ ^[0-9]+(\.[0-9]+)+$ ]]
[[ $stable_rev =~ ^[a-f0-9]{40}$ ]]

if (( $# == 1 )); then
  printf 'changed=%s\nchanged_channels=%s\nversion=%s\nrev=%s\nstable_version=%s\nstable_rev=%s\n' \
    "$changed" "$changed_channels" "$version" "$rev" "$stable_version" "$stable_rev" >>"$1"
else
  printf 'changed=%s\nchanged_channels=%s\nversion=%s\nrev=%s\nstable_version=%s\nstable_rev=%s\n' \
    "$changed" "$changed_channels" "$version" "$rev" "$stable_version" "$stable_rev"
fi
