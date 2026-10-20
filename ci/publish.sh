#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${CACHIX_AUTH_TOKEN:?CACHIX_AUTH_TOKEN must be set}"
: "${XO_NIXPKG_CACHIX_CACHE_NAME:?XO_NIXPKG_CACHIX_CACHE_NAME must be set}"
xo-nixpkg-publication-gate
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
cachix push "$XO_NIXPKG_CACHIX_CACHE_NAME" "${package_paths[@]}"
