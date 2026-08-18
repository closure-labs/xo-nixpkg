#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/bin"
cp "$root/nix/sources/xen-orchestra.json" "$temporary/xo.json"
cp "$root/nix/sources/libvhdi.json" "$temporary/libvhdi.json"

xo_version=$(jq -er .version "$temporary/xo.json")
xo_rev=$(jq -er .rev "$temporary/xo.json")
cat >"$temporary/commits.json" <<JSON
[{"sha":"$xo_rev","commit":{"message":"feat: release $xo_version (#1)"}}]
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
if [[ $1 == build ]]; then
  echo 'No-change updater unexpectedly built a package' >&2
  exit 99
fi
case "$*" in
  *xen-orchestra-ce.version*) jq -r .version "$XO_NIXPKG_XO_PIN_FILE" ;;
  *xen-orchestra-ce.src.rev*) jq -r .rev "$XO_NIXPKG_XO_PIN_FILE" ;;
  *) echo "Unexpected nix invocation: $*" >&2; exit 98 ;;
esac
SH
chmod +x "$temporary/bin/nix"
: >"$temporary/nix.log"

PATH="$temporary/bin:$PATH" \
NOOP_NIX_LOG="$temporary/nix.log" \
XO_NIXPKG_SOURCE_ROOT="$root" \
XO_NIXPKG_UPDATE_IN_DEV_SHELL=1 \
XO_NIXPKG_XO_PIN_FILE="$temporary/xo.json" \
XO_NIXPKG_COMMITS_JSON="$temporary/commits.json" \
  bash "$root/ci/update-xo.sh" --release "$temporary/xo-output"
grep -Fx 'changed=false' "$temporary/xo-output" >/dev/null
if grep -q '^build ' "$temporary/nix.log"; then
  echo 'No-change XO updater invoked nix build' >&2
  exit 1
fi

LIBVHDI_PIN_FILE="$temporary/libvhdi.json" \
LIBVHDI_RELEASES_JSON="$temporary/releases.json" \
XO_NIXPKG_SOURCE_ROOT="$root" \
  bash "$root/ci/update-libvhdi.sh" "$temporary/libvhdi-output"
grep -Fx 'changed=false' "$temporary/libvhdi-output" >/dev/null
