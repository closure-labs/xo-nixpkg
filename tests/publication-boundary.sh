#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/bin"
printf '#!%s\n' "$BASH" >"$work/bin/xo-nixpkg-publication-gate"
cat >>"$work/bin/xo-nixpkg-publication-gate" <<'SCRIPT'
exit 27
SCRIPT
for name in git gh cachix nix nix-store; do
  printf '#!%s\n' "$BASH" >"$work/bin/$name"
  cat >>"$work/bin/$name" <<'SCRIPT'
printf 'Side effect before live gate\n' >>"$BOUNDARY_LOG"
exit 1
SCRIPT
done
chmod +x "$work/bin/"*
export PATH="$work/bin:$PATH" BOUNDARY_LOG="$work/side-effects"
export CACHIX_AUTH_TOKEN=fixture XO_NIXPKG_CACHIX_CACHE_NAME=fixture
for leaf in publish tag-release tag-xo-release publish-release; do
  status=0
  bash "$root/ci/$leaf.sh" || status=$?
  if [[ $status != 27 ]]; then
    printf '%s bypassed failed live admission\n' "$leaf" >&2
    exit 1
  fi
  [[ ! -e $BOUNDARY_LOG ]]
done
printf 'Every distribution entrypoint rejected unavailable authority before external effects\n'
