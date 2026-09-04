#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

old_stable_rev=0000000000000000000000000000000000000000
old_latest_rev=1111111111111111111111111111111111111111
excluded_stable_rev=2222222222222222222222222222222222222222
latest_rev=3333333333333333333333333333333333333333
old_rolling_rev=4444444444444444444444444444444444444444
latest_yarn_hash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
latest_docs_yarn_hash=sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=

write_initial_state() {
  jq -n \
    --arg old_stable_rev "$old_stable_rev" \
    --arg old_latest_rev "$old_latest_rev" \
    --arg old_rolling_rev "$old_rolling_rev" \
    --arg latest_yarn_hash "$latest_yarn_hash" \
    --arg latest_docs_yarn_hash "$latest_docs_yarn_hash" '
    {
      schemaVersion: 2,
      owner: "vatesfr",
      repo: "xen-orchestra",
      excludedStableVersions: ["9.2"],
      channels: {
        latest: {
          version: "9.1.0", rev: $old_latest_rev,
          yarnHash: $latest_yarn_hash, docsYarnHash: $latest_docs_yarn_hash
        },
        stable: {
          version: "9.0.0", rev: $old_stable_rev,
          yarnHash: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
          docsYarnHash: "sha256-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
        },
        rolling: {
          version: "unstable-2026-08-01", rev: $old_rolling_rev,
          yarnHash: "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=",
          docsYarnHash: "sha256-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF="
        }
      }
    }
  ' >"$temporary/xo.json"

  {
    printf '%s\n' '{' '  inputs = {'
    printf '    xo-latest = {\n      url = "github:vatesfr/xen-orchestra/%s";\n      flake = false;\n    };\n' "$old_latest_rev"
    printf '    xo-stable = {\n      url = "github:vatesfr/xen-orchestra/%s";\n      flake = false;\n    };\n' "$old_stable_rev"
    printf '    xo-rolling = {\n      url = "github:vatesfr/xen-orchestra/%s";\n      flake = false;\n    };\n' "$old_rolling_rev"
    printf '%s\n' '  };' '}'
  } >"$temporary/flake.nix"
}

mkdir -p "$temporary/current/docs" "$temporary/candidate/docs"
printf '%s\n' '"@turbo/linux-64@2.9.17":' '  version "2.9.17"' \
  >"$temporary/current/yarn.lock"
cp "$temporary/current/yarn.lock" "$temporary/candidate/yarn.lock"
printf '%s\n' docs-lock >"$temporary/current/docs/yarn.lock"
cp "$temporary/current/docs/yarn.lock" "$temporary/candidate/docs/yarn.lock"
printf '## **9.2.1** (2026-09-02)\n' >"$temporary/candidate/CHANGELOG.md"
write_initial_state

cat >"$temporary/commits.json" <<JSON
[
  {"sha":"5555555555555555555555555555555555555555","commit":{"message":"feat(lite): 0.25.0 (#11000)"}},
  {"sha":"$latest_rev","commit":{"message":"feat: release 9.2.1 (#11002)\n\nNormal XO release"}},
  {"sha":"$excluded_stable_rev","commit":{"message":"feat: release 9.2 (#11001)"}},
  {"sha":"$old_latest_rev","commit":{"message":"feat: release 9.1.0 (#10229)"}}
]
JSON
jq -cn --arg storePath "$temporary/candidate" \
  '{hash:"sha256-GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG=",storePath:$storePath}' \
  >"$temporary/prefetch.json"

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
jq -e \
  --arg latest "$latest_rev" \
  --arg stable "$old_latest_rev" \
  --arg yarnHash "$latest_yarn_hash" \
  --arg docsYarnHash "$latest_docs_yarn_hash" '
  .schemaVersion == 2 and
  .excludedStableVersions == ["9.2"] and
  .channels.latest.version == "9.2.1" and
  .channels.latest.rev == $latest and
  .channels.stable.version == "9.1.0" and
  .channels.stable.rev == $stable and
  .channels.latest.yarnHash == $yarnHash and
  .channels.latest.docsYarnHash == $docsYarnHash and
  (.channels.latest | has("platformTools") | not) and
  (.channels.latest | has("hash") | not)
' "$temporary/xo.json" >/dev/null
grep -F "github:vatesfr/xen-orchestra/$latest_rev" "$temporary/flake.nix" >/dev/null
grep -F "github:vatesfr/xen-orchestra/$old_latest_rev" "$temporary/flake.nix" >/dev/null

# Exact current channels are no-ops and do not prefetch or build anything.
XO_NIXPKG_PREFETCH_JSON="$temporary/missing-prefetch.json" run_update --release >/dev/null

# XO-prefixed historical markers remain supported.
sed 's/feat: release 9.2.1/feat: release XO 9.2.1/' \
  "$temporary/commits.json" >"$temporary/historical.json"
XO_NIXPKG_COMMITS_JSON="$temporary/historical.json" run_update --release >/dev/null

# Paginated responses larger than ARG_MAX stay in files instead of becoming
# jq command-line arguments. Page two completes the two-release selection.
jq -n --arg latest_rev "$latest_rev" --arg excluded_stable_rev "$excluded_stable_rev" '
  [
    {sha:$latest_rev,commit:{message:"feat: release 9.2.1 (#11002)"}},
    {sha:$excluded_stable_rev,commit:{message:"feat: release 9.2 (#11001)"}}
  ] +
  [range(0; 35000) as $index | {
    sha:("f" * 40),
    commit:{message:("chore: large pagination fixture " + ($index | tostring) + ("x" * 80))}
  }]
' >"$temporary/page-1.json"
jq -n --arg stable_rev "$old_latest_rev" \
  '[{sha:$stable_rev,commit:{message:"feat: release 9.1.0 (#10229)"}}]' \
  >"$temporary/page-2.json"
mkdir -p "$temporary/bin"
printf '#!%s\n' "$BASH" >"$temporary/bin/curl"
cat >>"$temporary/bin/curl" <<'SH'
set -euo pipefail
url=${!#}
case "$url" in
  *page=1) cat "$LARGE_PAGE_ONE" ;;
  *page=2) cat "$LARGE_PAGE_TWO" ;;
  *) printf '[]\n' ;;
esac
SH
chmod +x "$temporary/bin/curl"
PATH="$temporary/bin:$PATH" \
LARGE_PAGE_ONE="$temporary/page-1.json" \
LARGE_PAGE_TWO="$temporary/page-2.json" \
XO_NIXPKG_SOURCE_ROOT="$root" \
XO_NIXPKG_XO_PIN_FILE="$temporary/xo.json" \
XO_NIXPKG_FLAKE_FILE="$temporary/flake.nix" \
XO_NIXPKG_PREFETCH_JSON="$temporary/missing-prefetch.json" \
XO_NIXPKG_CURRENT_SOURCE="$temporary/current" \
  bash "$root/scripts/update.sh" --release >/dev/null

# Non-array GitHub payloads are rejected before release classification.
printf '{"message":"rate limited"}\n' >"$temporary/malformed.json"
if XO_NIXPKG_COMMITS_JSON="$temporary/malformed.json" run_update --release >/dev/null 2>&1; then
  echo 'Malformed GitHub commit response was accepted' >&2
  exit 1
fi

# Lite and technical markers cannot form the two official release channels.
jq '[.[0], {sha:"6666666666666666666666666666666666666666",commit:{message:"feat: technical release (#10999)"}}]' \
  "$temporary/commits.json" >"$temporary/non-xo.json"
if XO_NIXPKG_COMMITS_JSON="$temporary/non-xo.json" run_update --release >/dev/null 2>&1; then
  echo 'XO Lite or technical releases were accepted as official channels' >&2
  exit 1
fi

# The latest release marker and root changelog must agree. This fixture is
# synthetic so a real upstream release cannot silently invalidate CI.
write_initial_state
printf '## **9.2.2** (2026-09-03)\n' >"$temporary/candidate/CHANGELOG.md"
if run_update --release >/dev/null 2>&1; then
  echo 'Mismatched XO release marker and changelog were accepted' >&2
  exit 1
fi

# A discovered release older than the current latest cannot downgrade channels.
write_initial_state
jq '.channels.latest.version = "99.0.0"' "$temporary/xo.json" \
  >"$temporary/downgrade.json"
mv "$temporary/downgrade.json" "$temporary/xo.json"
if run_update --release >/dev/null 2>&1; then
  echo 'Older XO release was not rejected' >&2
  exit 1
fi

# Changed rolling lockfiles exercise both fixed-output hash calculations.
write_initial_state
printf '\n# root lock changed\n' >>"$temporary/candidate/yarn.lock"
printf '\n# docs lock changed\n' >>"$temporary/candidate/docs/yarn.lock"
printf '#!%s\n' "$(command -v bash)" >"$temporary/bin/nix-build"
cat >>"$temporary/bin/nix-build" <<'SH'
set -euo pipefail
printf '%s\n' "$*" >>"$PREFETCH_NIX_LOG"
case " $* " in
  *' --arg normalized true '*) hash='sha256-HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH=' ;;
  *' --arg normalized false '*) hash='sha256-IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII=' ;;
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
  .channels.rolling.yarnHash == "sha256-HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH=" and
  .channels.rolling.docsYarnHash == "sha256-IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII="
' "$temporary/xo.json" >/dev/null
grep -F "github:vatesfr/xen-orchestra/$rolling_rev" "$temporary/flake.nix" >/dev/null
grep -F -- "$root/nix/prefetch-yarn-deps.nix" "$temporary/prefetch-nix.log" >/dev/null
grep -F -- '--argstr yarnLock' "$temporary/prefetch-nix.log" >/dev/null

printf 'XO channel update fixtures passed\n'
