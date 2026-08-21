#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/bin"

printf '#!%s\n' "$BASH" >"$temporary/fake-update.sh"
cat >>"$temporary/fake-update.sh" <<'SH'
set -euo pipefail
pin_file=${XO_NIXPKG_XO_PIN_FILE:?}
flake_file=${XO_NIXPKG_FLAKE_FILE:?}
for channel in ${EFFECT_CHANNELS:-}; do
  case "$channel" in
    latest) rev=1111111111111111111111111111111111111111; version=9.1.0 ;;
    stable) rev=2222222222222222222222222222222222222222; version=9.0.0 ;;
    rolling) rev=3333333333333333333333333333333333333333; version=unstable-2026-08-21 ;;
    *) exit 2 ;;
  esac
  old_rev=$(jq -er --arg channel "$channel" '.channels[$channel].rev' "$pin_file")
  temporary_pin=$(mktemp)
  jq --arg channel "$channel" --arg rev "$rev" --arg version "$version" \
    '.channels[$channel].rev = $rev | .channels[$channel].version = $version' \
    "$pin_file" >"$temporary_pin"
  mv "$temporary_pin" "$pin_file"
  sed -i "s|github:vatesfr/xen-orchestra/$old_rev|github:vatesfr/xen-orchestra/$rev|" "$flake_file"
done
SH
chmod +x "$temporary/fake-update.sh"

printf '#!%s\n' "$BASH" >"$temporary/bin/nix"
cat >>"$temporary/bin/nix" <<'SH'
set -euo pipefail
printf '%s\n' "$*" >>"$EFFECT_NIX_LOG"
SH
chmod +x "$temporary/bin/nix"

run_effect() {
  local channels=$1 mode=$2 expected=$3 output=$temporary/output
  cp "$root/nix/sources/xen-orchestra.json" "$temporary/xo.json"
  cp "$root/flake.nix" "$temporary/flake.nix"
  : >"$temporary/nix.log"
  EFFECT_CHANNELS="$channels" \
  EFFECT_NIX_LOG="$temporary/nix.log" \
  PATH="$temporary/bin:$PATH" \
  XO_NIXPKG_SOURCE_ROOT="$root" \
  XO_NIXPKG_UPDATE_XO_SOURCE_COMMAND="$temporary/fake-update.sh" \
  XO_NIXPKG_XO_PIN_FILE="$temporary/xo.json" \
  XO_NIXPKG_FLAKE_FILE="$temporary/flake.nix" \
    bash "$root/ci/update-xo.sh" "$mode" "$output"
  grep -Fx "changed_channels=$expected" "$output" >/dev/null
  rm -f "$output"
}

run_effect rolling --rolling rolling
grep -Fx 'flake lock --accept-flake-config --update-input xo-rolling' "$temporary/nix.log" >/dev/null
run_effect latest --release latest
grep -Fx 'flake lock --accept-flake-config --update-input xo-latest' "$temporary/nix.log" >/dev/null
run_effect stable --release stable
grep -Fx 'flake lock --accept-flake-config --update-input xo-stable' "$temporary/nix.log" >/dev/null
run_effect 'latest stable' --release latest,stable
grep -Fx 'flake lock --accept-flake-config --update-input xo-latest --update-input xo-stable' "$temporary/nix.log" >/dev/null
run_effect '' --release ''
[[ ! -s $temporary/nix.log ]]

printf 'Semantic XO update effect fixtures passed\n'
