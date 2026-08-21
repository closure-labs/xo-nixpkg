#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/bin"

printf '#!%s\n' "$BASH" >"$temporary/bin/nix"
cat >>"$temporary/bin/nix" <<'SH'
set -euo pipefail
printf '%s\n' "$*" >>"$PREWARM_NIX_LOG"
case "$1 $2" in
  'build --accept-flake-config') printf '%s\n' /nix/store/rolling-candidate ;;
  'eval --accept-flake-config') printf '%s' "${FAKE_ROLLING_PATH:-/nix/store/rolling-candidate}" ;;
  'path-info --recursive') printf '%s\n' /nix/store/dependency /nix/store/rolling-candidate ;;
  *) printf 'Unexpected nix command: %s\n' "$*" >&2; exit 2 ;;
esac
SH
printf '#!%s\n' "$BASH" >"$temporary/bin/cachix"
cat >>"$temporary/bin/cachix" <<'SH'
set -euo pipefail
printf '%s\n' "$*" >"$PREWARM_CACHIX_LOG"
SH
chmod +x "$temporary/bin/nix" "$temporary/bin/cachix"
: >"$temporary/nix.log"

CACHIX_AUTH_TOKEN=fixture \
PREWARM_NIX_LOG="$temporary/nix.log" \
PREWARM_CACHIX_LOG="$temporary/cachix.log" \
PATH="$temporary/bin:$PATH" \
XO_NIXPKG_SOURCE_ROOT="$root" \
  bash "$root/ci/prewarm-rolling.sh" "$temporary/output"
grep -Fx 'cachix push xen-orchestra-ce /nix/store/rolling-candidate' \
  < <(sed 's/^/cachix /' "$temporary/cachix.log") >/dev/null
grep -Fx 'candidate_path=/nix/store/rolling-candidate' "$temporary/output" >/dev/null
grep -Fx 'closure_path_count=2' "$temporary/output" >/dev/null
grep -F '#rolling-candidate' "$temporary/nix.log" >/dev/null

if CACHIX_AUTH_TOKEN=fixture \
  FAKE_ROLLING_PATH=/nix/store/not-the-candidate \
  PREWARM_NIX_LOG="$temporary/nix.log" \
  PREWARM_CACHIX_LOG="$temporary/cachix.log" \
  PATH="$temporary/bin:$PATH" \
  XO_NIXPKG_SOURCE_ROOT="$root" \
    bash "$root/ci/prewarm-rolling.sh" >/dev/null 2>&1; then
  echo 'Prewarming accepted a target that did not match rolling' >&2
  exit 1
fi

printf 'Rolling candidate prewarm fixtures passed\n'
