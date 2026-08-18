#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

mkdir -p "$temporary/current/docs" "$temporary/candidate/docs"
cat >"$temporary/current/yarn.lock" <<'LOCK'
"@esbuild/linux-x64@0.25.5":
  version "0.25.5"

"@turbo/linux-64@2.5.6":
  version "2.5.6"

"@rollup/rollup-linux-x64-gnu@4.44.1":
  version "4.44.1"
LOCK
cp "$temporary/current/yarn.lock" "$temporary/candidate/yarn.lock"
printf '%s\n' docs-lock >"$temporary/current/docs/yarn.lock"
cp "$temporary/current/docs/yarn.lock" "$temporary/candidate/docs/yarn.lock"
printf '## **6.8.0** (2026-08-18)\n' >"$temporary/candidate/CHANGELOG.md"
cp "$root/nix/sources/xen-orchestra.json" "$temporary/xo.json"

cat >"$temporary/commits.json" <<'JSON'
[
  {
    "sha": "1111111111111111111111111111111111111111",
    "commit": {"message": "feat(lite): 0.25.0 (#11000)"}
  },
  {
    "sha": "2222222222222222222222222222222222222222",
    "commit": {"message": "feat: technical release (#10999)"}
  },
  {
    "sha": "3333333333333333333333333333333333333333",
    "commit": {"message": "feat: release 6.8.0 (#11001)\n\nNormal XO release"}
  }
]
JSON
jq -cn --arg storePath "$temporary/candidate" \
  '{hash:"sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",storePath:$storePath}' >"$temporary/prefetch.json"

XO_NIXPKG_UPDATE_IN_DEV_SHELL=1 \
XO_NIXPKG_XO_PIN_FILE="$temporary/xo.json" \
XO_NIXPKG_COMMITS_JSON="$temporary/commits.json" \
XO_NIXPKG_PREFETCH_JSON="$temporary/prefetch.json" \
XO_NIXPKG_CURRENT_SOURCE="$temporary/current" \
  bash "$root/scripts/update.sh" --release

jq -e '
  .schemaVersion == 1 and
  .version == "6.8.0" and
  .rev == "3333333333333333333333333333333333333333" and
  .hash == "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" and
  .platformTools["x86_64-linux"].turbo.version == "2.5.6"
' "$temporary/xo.json" >/dev/null

# Exact current releases are no-ops and must not need a source prefetch.
XO_NIXPKG_UPDATE_IN_DEV_SHELL=1 \
XO_NIXPKG_XO_PIN_FILE="$temporary/xo.json" \
XO_NIXPKG_COMMITS_JSON="$temporary/commits.json" \
XO_NIXPKG_PREFETCH_JSON="$temporary/missing-prefetch.json" \
XO_NIXPKG_CURRENT_SOURCE="$temporary/current" \
  bash "$root/scripts/update.sh" --release >/dev/null

# Historical unscoped markers remain supported.
jq '.version = "6.7.1" | .rev = "40dede9e11c90562df5cb46c6a83a9d91efedae1"' \
  "$root/nix/sources/xen-orchestra.json" >"$temporary/xo.json"
sed 's/feat: release 6.8.0/feat: release XO 6.8.0/' "$temporary/commits.json" >"$temporary/historical.json"
XO_NIXPKG_UPDATE_IN_DEV_SHELL=1 \
XO_NIXPKG_XO_PIN_FILE="$temporary/xo.json" \
XO_NIXPKG_COMMITS_JSON="$temporary/historical.json" \
XO_NIXPKG_PREFETCH_JSON="$temporary/prefetch.json" \
XO_NIXPKG_CURRENT_SOURCE="$temporary/current" \
  bash "$root/scripts/update.sh" --release >/dev/null

# Lite and technical markers alone never select a normal XO release.
jq '.[0:2]' "$temporary/commits.json" >"$temporary/non-xo.json"
if XO_NIXPKG_UPDATE_IN_DEV_SHELL=1 \
  XO_NIXPKG_XO_PIN_FILE="$temporary/xo.json" \
  XO_NIXPKG_COMMITS_JSON="$temporary/non-xo.json" \
  bash "$root/scripts/update.sh" --release >/dev/null 2>&1; then
  echo 'XO Lite or technical release was accepted as a normal XO release' >&2
  exit 1
fi

# The release marker and root changelog must agree.
jq '.version = "6.7.1" | .rev = "40dede9e11c90562df5cb46c6a83a9d91efedae1"' \
  "$root/nix/sources/xen-orchestra.json" >"$temporary/xo.json"
printf '## **6.8.1** (2026-08-18)\n' >"$temporary/candidate/CHANGELOG.md"
if XO_NIXPKG_UPDATE_IN_DEV_SHELL=1 \
  XO_NIXPKG_XO_PIN_FILE="$temporary/xo.json" \
  XO_NIXPKG_COMMITS_JSON="$temporary/commits.json" \
  XO_NIXPKG_PREFETCH_JSON="$temporary/prefetch.json" \
  XO_NIXPKG_CURRENT_SOURCE="$temporary/current" \
  bash "$root/scripts/update.sh" --release >/dev/null 2>&1; then
  echo 'Mismatched XO release marker and changelog were accepted' >&2
  exit 1
fi

# A valid older release marker must not downgrade the package.
jq '.version = "6.9.0" | .rev = "9999999999999999999999999999999999999999"' \
  "$root/nix/sources/xen-orchestra.json" >"$temporary/xo.json"
if XO_NIXPKG_UPDATE_IN_DEV_SHELL=1 \
  XO_NIXPKG_XO_PIN_FILE="$temporary/xo.json" \
  XO_NIXPKG_COMMITS_JSON="$temporary/commits.json" \
  bash "$root/scripts/update.sh" --release >/dev/null 2>&1; then
  echo 'Older XO release was not rejected' >&2
  exit 1
fi
