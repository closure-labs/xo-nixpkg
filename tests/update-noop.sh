#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/bin"
cp "$root/nix/sources/xen-orchestra.json" "$temporary/xo.json"
cp "$root/flake.nix" "$temporary/flake.nix"
cp "$root/nix/sources/libvhdi.json" "$temporary/libvhdi.json"

xo_version=$(jq -er .channels.latest.version "$temporary/xo.json")
xo_rev=$(jq -er .channels.latest.rev "$temporary/xo.json")
stable_version=$(jq -er .channels.stable.version "$temporary/xo.json")
stable_rev=$(jq -er .channels.stable.rev "$temporary/xo.json")
cat >"$temporary/commits.json" <<JSON
[
  {"sha":"$xo_rev","commit":{"message":"feat: release $xo_version (#1)"}},
  {"sha":"$stable_rev","commit":{"message":"feat: release $stable_version (#2)"}}
]
JSON

vhdi_version=$(jq -er .version "$temporary/libvhdi.json")
vhdi_url=$(jq -er .url "$temporary/libvhdi.json")
cat >"$temporary/releases.json" <<JSON
[{"tag_name":"$vhdi_version","draft":false,"prerelease":true,"assets":[{"name":"libvhdi-alpha-$vhdi_version.tar.gz","browser_download_url":"$vhdi_url"}]}]
JSON

printf '#!%s\n' "$(command -v bash)" >"$temporary/bin/nix"
cat >>"$temporary/bin/nix" <<'SH'
set -euo pipefail
printf '%s\n' "$*" >>"$NOOP_NIX_LOG"
echo "No-change updater unexpectedly invoked Nix: $*" >&2
exit 99
SH
chmod +x "$temporary/bin/nix"
: >"$temporary/nix.log"

PATH="$temporary/bin:$PATH" \
NOOP_NIX_LOG="$temporary/nix.log" \
XO_NIXPKG_SOURCE_ROOT="$root" \
XO_NIXPKG_UPDATE_IN_DEV_SHELL=1 \
XO_NIXPKG_UPDATE_XO_SOURCE_COMMAND="$root/scripts/update.sh" \
XO_NIXPKG_XO_PIN_FILE="$temporary/xo.json" \
XO_NIXPKG_FLAKE_FILE="$temporary/flake.nix" \
XO_NIXPKG_COMMITS_JSON="$temporary/commits.json" \
  bash "$root/ci/update-xo.sh" --release "$temporary/xo-output"
grep -Fx 'changed=false' "$temporary/xo-output" >/dev/null
if [[ -s $temporary/nix.log ]]; then
  echo 'No-change XO updater invoked Nix' >&2
  exit 1
fi

LIBVHDI_PIN_FILE="$temporary/libvhdi.json" \
LIBVHDI_RELEASES_JSON="$temporary/releases.json" \
XO_NIXPKG_SOURCE_ROOT="$root" \
XO_NIXPKG_UPDATE_LIBVHDI_SOURCE_COMMAND="$root/scripts/update-libvhdi.sh" \
  bash "$root/ci/update-libvhdi.sh" "$temporary/libvhdi-output"
grep -Fx 'changed=false' "$temporary/libvhdi-output" >/dev/null
