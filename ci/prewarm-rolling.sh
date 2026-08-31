#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${CACHIX_AUTH_TOKEN:?CACHIX_AUTH_TOKEN must be set}"
: "${XO_NIXPKG_CACHIX_CACHE_NAME:?XO_NIXPKG_CACHIX_CACHE_NAME must be set}"

repo_root=${XO_NIXPKG_SOURCE_ROOT:-$PWD}
flake_ref="git+file://$repo_root"
output_file=${1:-}

mapfile -t candidate_paths < <(
  nix build --accept-flake-config --no-link --print-out-paths \
    "$flake_ref#rolling-candidate"
)
if (( ${#candidate_paths[@]} != 1 )); then
  printf 'Expected exactly one rolling candidate output, got %s\n' \
    "${#candidate_paths[@]}" >&2
  exit 1
fi

candidate_path=${candidate_paths[0]}
rolling_path=$(nix eval --accept-flake-config --raw \
  "$flake_ref#packages.x86_64-linux.rolling.outPath")
if [[ $candidate_path != "$rolling_path" ]]; then
  printf 'Rolling candidate %s does not match rolling package %s\n' \
    "$candidate_path" "$rolling_path" >&2
  exit 1
fi

closure_path_count=$(nix path-info --recursive "$candidate_path" | wc -l)
(( closure_path_count > 0 ))
cachix push "$XO_NIXPKG_CACHIX_CACHE_NAME" "$candidate_path"

if [[ -n $output_file ]]; then
  printf 'candidate_path=%s\nclosure_path_count=%s\n' \
    "$candidate_path" "$closure_path_count" >>"$output_file"
else
  printf 'Prewarmed rolling candidate %s (%s closure paths)\n' \
    "$candidate_path" "$closure_path_count"
fi
