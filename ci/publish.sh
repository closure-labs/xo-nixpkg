#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${CACHIX_AUTH_TOKEN:?CACHIX_AUTH_TOKEN must be set}"
: "${XO_NIXPKG_CACHIX_CACHE_NAME:?XO_NIXPKG_CACHIX_CACHE_NAME must be set}"
xo-nixpkg-publication-gate
: "${XO_NIXPKG_CACHIX_CACHE_URL:?XO_NIXPKG_CACHIX_CACHE_URL must be set}"
# Inspect public identities before importing or transferring any closure.
destination_state=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/publication-cache.XXXXXX")
trap 'rm -f -- "$destination_state"' EXIT
python3 "${PUBLICATION_DESTINATIONS_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/destinations.py}" cache --product "$XO_NIXPKG_EVIDENCE/product.json" --cache-url "$XO_NIXPKG_CACHIX_CACHE_URL" ${PUBLICATION_CACHE_RECEIPT:+--receipt "$PUBLICATION_CACHE_RECEIPT"} >"$destination_state"
if [[ $(jq -er .status "$destination_state") == verified ]]; then
  xo-nixpkg-publication-gate
  echo 'Public cache verified; no closure import or upload required.'
  exit 0
fi
xo-nixpkg-restore-products
mapfile -t package_paths < <(jq -er '.products[].storePath, .roots[].storePath' "$XO_NIXPKG_EVIDENCE/product.json")
(( ${#package_paths[@]} == 8 ))
# Re-realize exact approved paths only; this credentialed process never builds
# candidate source or executes a candidate derivation.
for package_path in "${package_paths[@]}"; do
  nix-store --realise "$package_path"
  expected=$(jq -er --arg path "$package_path" '.products[], .roots[] | select(.storePath == $path) | .narHash' "$XO_NIXPKG_EVIDENCE/product.json")
  actual=$(nix path-info --json "$package_path" | jq -er 'if type == "array" then .[0].narHash else .[].narHash end')
  [[ $actual == "$expected" ]]
done
xo-nixpkg-publication-gate
mapfile -t missing_paths < <(jq -er '.missing[]' "$destination_state")
cachix push "$XO_NIXPKG_CACHIX_CACHE_NAME" "${missing_paths[@]}"
# A successful upload can leave an existing same-path object untouched. Confirm
# the public cache serves the approved bytes before the controller checkpoints
# publication or publishes a downstream handoff. Query the remote store directly
# and bypass both positive and negative local narinfo metadata caches.
if ! remote_info=$(timeout --signal=TERM --kill-after=10s 120s \
  nix path-info --store "$XO_NIXPKG_CACHIX_CACHE_URL" --json \
  --option narinfo-cache-positive-ttl 0 --option narinfo-cache-negative-ttl 0 \
  "${package_paths[@]}" 2>/dev/null); then
  echo 'Public cache readback failed' >&2
  exit 1
fi
if ! jq -se --slurpfile product "$XO_NIXPKG_EVIDENCE/product.json" '
  (if length == 1 then .[0] else error("invalid remote JSON stream") end)
  |
  (if type == "array" then map({storePath: .path, narHash})
   elif type == "object" then to_entries | map({storePath: .key, narHash: .value.narHash})
   else error("invalid remote path metadata") end | sort_by(.storePath))
  == ([$product[0].products[], $product[0].roots[]]
      | map({storePath, narHash}) | sort_by(.storePath))
' <<< "$remote_info" >/dev/null 2>&1; then
  echo 'Public cache paths or NAR hashes differ from the approved product' >&2
  exit 1
fi

# Persist only fresh remote proof; an older completion is never sufficient.
python3 "${PUBLICATION_DESTINATIONS_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/destinations.py}" cache --product "$XO_NIXPKG_EVIDENCE/product.json" --cache-url "$XO_NIXPKG_CACHIX_CACHE_URL" --require-verified ${PUBLICATION_CACHE_RECEIPT:+--receipt "$PUBLICATION_CACHE_RECEIPT"}
