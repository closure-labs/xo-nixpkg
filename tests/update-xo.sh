#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

mkdir -p "$temporary/current/docs" "$temporary/candidate/docs"
cat >"$temporary/current/yarn.lock" <<'LOCK'
"@turbo/linux-64@2.9.17":
  version "2.9.17"
LOCK
cp "$temporary/current/yarn.lock" "$temporary/candidate/yarn.lock"
printf '%s\n' docs-lock >"$temporary/current/docs/yarn.lock"
cp "$temporary/current/docs/yarn.lock" "$temporary/candidate/docs/yarn.lock"
printf '## **6.8.0** (2026-08-20)\n' >"$temporary/candidate/CHANGELOG.md"
cp "$root/nix/sources/xen-orchestra.json" "$temporary/xo.json"
cp "$root/flake.nix" "$temporary/flake.nix"

latest_rev=3333333333333333333333333333333333333333
stable_rev=$(jq -er '.channels.latest.rev' "$temporary/xo.json")
cat >"$temporary/commits.json" <<JSON
[
  {"sha":"1111111111111111111111111111111111111111","commit":{"message":"feat(lite): 0.25.0 (#11000)"}},
  {"sha":"$latest_rev","commit":{"message":"feat: release 6.8.0 (#11001)\n\nNormal XO release"}},
  {"sha":"$stable_rev","commit":{"message":"feat: release 6.7.1 (#10229)"}}
]
JSON
jq -cn --arg storePath "$temporary/candidate" \
  '{hash:"sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",storePath:$storePath}' >"$temporary/prefetch.json"

run_update() {
  XO_NIXPKG_SOURCE_ROOT="$root" \
  XO_NIXPKG_XO_PIN_FILE="$temporary/xo.json" \
  XO_NIXPKG_FLAKE_FILE="$temporary/flake.nix" \
  XO_NIXPKG_COMMITS_JSON="${XO_NIXPKG_COMMITS_JSON:-$temporary/commits.json}" \
  XO_NIXPKG_PREFETCH_JSON="${XO_NIXPKG_PREFETCH_JSON:-$temporary/prefetch.json}" \
  XO_NIXPKG_CURRENT_SOURCE="$temporary/current" \
    bash "$root/scripts/update.sh" "$@"
}

run_update --release
jq -e --arg latest "$latest_rev" --arg stable "$stable_rev" '
  .schemaVersion == 2 and
  .channels.latest.version == "6.8.0" and
  .channels.latest.rev == $latest and
  .channels.stable.version == "6.7.1" and
  .channels.stable.rev == $stable and
  .channels.latest.yarnHash == "sha256-8qv/ak3fYY2ODpWN3WZO5wrXokiK6CH8vGq49cmZlvA=" and
  (.channels.latest | has("platformTools") | not) and
  (.channels.latest | has("hash") | not)
' "$temporary/xo.json" >/dev/null
grep -F "github:vatesfr/xen-orchestra/$latest_rev" "$temporary/flake.nix" >/dev/null
grep -F "github:vatesfr/xen-orchestra/$stable_rev" "$temporary/flake.nix" >/dev/null

# Exact current channels are no-ops and do not prefetch or build anything.
XO_NIXPKG_PREFETCH_JSON="$temporary/missing-prefetch.json" run_update --release >/dev/null

# XO-prefixed historical markers remain supported.
sed 's/feat: release 6.8.0/feat: release XO 6.8.0/' "$temporary/commits.json" >"$temporary/historical.json"
XO_NIXPKG_COMMITS_JSON="$temporary/historical.json" run_update --release >/dev/null

# Lite and technical markers cannot form the two official release channels.
jq '[.[0], {sha:"2222222222222222222222222222222222222222",commit:{message:"feat: technical release (#10999)"}}]' \
  "$temporary/commits.json" >"$temporary/non-xo.json"
if XO_NIXPKG_COMMITS_JSON="$temporary/non-xo.json" run_update --release >/dev/null 2>&1; then
  echo 'XO Lite or technical releases were accepted as official channels' >&2
  exit 1
fi

# The latest release marker and root changelog must agree.
jq --arg rev "$stable_rev" '.channels.latest.version = "6.7.1" | .channels.latest.rev = $rev' \
  "$root/nix/sources/xen-orchestra.json" >"$temporary/xo.json"
printf '## **6.8.1** (2026-08-20)\n' >"$temporary/candidate/CHANGELOG.md"
if run_update --release >/dev/null 2>&1; then
  echo 'Mismatched XO release marker and changelog were accepted' >&2
  exit 1
fi

# A discovered release older than the current latest cannot downgrade channels.
jq '.channels.latest.version = "6.9.0"' "$root/nix/sources/xen-orchestra.json" >"$temporary/xo.json"
if run_update --release >/dev/null 2>&1; then
  echo 'Older XO release was not rejected' >&2
  exit 1
fi

# Changed rolling lockfiles exercise both fixed-output hash calculations.
cp "$root/nix/sources/xen-orchestra.json" "$temporary/xo.json"
cp "$root/flake.nix" "$temporary/flake.nix"
printf '## **6.8.0** (2026-08-20)\n' >"$temporary/candidate/CHANGELOG.md"
printf '\n# root lock changed\n' >>"$temporary/candidate/yarn.lock"
printf '\n# docs lock changed\n' >>"$temporary/candidate/docs/yarn.lock"
mkdir -p "$temporary/bin"
printf '#!%s\n' "$(command -v bash)" >"$temporary/bin/nix-build"
cat >>"$temporary/bin/nix-build" <<'SH'
set -euo pipefail
printf '%s\n' "$*" >>"$PREFETCH_NIX_LOG"
case " $* " in
  *' --arg normalized true '*) hash='sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=' ;;
  *' --arg normalized false '*) hash='sha256-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=' ;;
  *) echo 'missing normalized argument' >&2; exit 2 ;;
esac
printf 'error: hash mismatch\n  got:    %s\n' "$hash" >&2
exit 1
SH
chmod +x "$temporary/bin/nix-build"
: >"$temporary/prefetch-nix.log"

rolling_rev=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
PATH="$temporary/bin:$PATH" \
PREFETCH_NIX_LOG="$temporary/prefetch-nix.log" \
XO_NIXPKG_NIXPKGS_PATH=/nix/store/test-nixpkgs \
XO_NIXPKG_UPSTREAM_REV="$rolling_rev" \
XO_NIXPKG_UPSTREAM_DATE=2026-08-20 \
  run_update --rolling >/dev/null

jq -e --arg rev "$rolling_rev" '
  .channels.rolling.version == "unstable-2026-08-20" and
  .channels.rolling.rev == $rev and
  .channels.rolling.yarnHash == "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=" and
  .channels.rolling.docsYarnHash == "sha256-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
' "$temporary/xo.json" >/dev/null
grep -F "github:vatesfr/xen-orchestra/$rolling_rev" "$temporary/flake.nix" >/dev/null
grep -F -- "$root/nix/prefetch-yarn-deps.nix" "$temporary/prefetch-nix.log" >/dev/null
grep -F -- '--argstr yarnLock' "$temporary/prefetch-nix.log" >/dev/null

printf 'XO channel update fixtures passed\n'
