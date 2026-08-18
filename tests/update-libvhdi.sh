#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

write_pin() {
  local version=$1
  jq --arg version "$version" '
    .version = $version |
    .url = "https://github.com/libyal/libvhdi/releases/download/" + $version + "/libvhdi-alpha-" + $version + ".tar.gz"
  ' "$root/nix/sources/libvhdi.json" >"$temporary/sources.json"
}

cat >"$temporary/releases.json" <<'JSON'
[
  {
    "tag_name": "20261231",
    "draft": false,
    "prerelease": true,
    "assets": [
      {
        "name": "libvhdi-alpha-20261231.tar.gz",
        "browser_download_url": "https://github.com/libyal/libvhdi/releases/download/20261231/libvhdi-alpha-20261231.tar.gz"
      }
    ]
  },
  {
    "tag_name": "not-a-date",
    "draft": false,
    "prerelease": false,
    "assets": []
  }
]
JSON
printf '%s\n' '{"hash":"sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}' >"$temporary/prefetch.json"

write_pin 20251119
LIBVHDI_PIN_FILE="$temporary/sources.json" \
LIBVHDI_RELEASES_JSON="$temporary/releases.json" \
LIBVHDI_PREFETCH_JSON="$temporary/prefetch.json" \
  bash "$root/scripts/update-libvhdi.sh"
jq -e '
  .version == "20261231" and
  .hash == "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" and
  .type == "Url" and
  .unpack == true
' "$temporary/sources.json" >/dev/null

write_pin 20270101
if LIBVHDI_PIN_FILE="$temporary/sources.json" \
  LIBVHDI_RELEASES_JSON="$temporary/releases.json" \
  LIBVHDI_PREFETCH_JSON="$temporary/prefetch.json" \
  bash "$root/scripts/update-libvhdi.sh" >/dev/null 2>&1; then
  echo 'Older libvhdi release was not rejected' >&2
  exit 1
fi

jq '.[0].assets += [.[0].assets[0]]' "$temporary/releases.json" >"$temporary/duplicate.json"
write_pin 20251119
if LIBVHDI_PIN_FILE="$temporary/sources.json" \
  LIBVHDI_RELEASES_JSON="$temporary/duplicate.json" \
  LIBVHDI_PREFETCH_JSON="$temporary/prefetch.json" \
  bash "$root/scripts/update-libvhdi.sh" >/dev/null 2>&1; then
  echo 'Release with duplicate matching assets was not rejected' >&2
  exit 1
fi

jq '.[0].assets = []' "$temporary/releases.json" >"$temporary/malformed.json"
write_pin 20251119
if LIBVHDI_PIN_FILE="$temporary/sources.json" \
  LIBVHDI_RELEASES_JSON="$temporary/malformed.json" \
  LIBVHDI_PREFETCH_JSON="$temporary/prefetch.json" \
  bash "$root/scripts/update-libvhdi.sh" >/dev/null 2>&1; then
  echo 'Release without its matching asset was not rejected' >&2
  exit 1
fi
