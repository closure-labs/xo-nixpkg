#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${CACHIX_AUTH_TOKEN:?CACHIX_AUTH_TOKEN must be set}"
: "${XO_NIXPKG_PUBLISH_PLAN:?XO_NIXPKG_PUBLISH_PLAN must be set}"

manifest=$(mktemp)
trap 'rm -f -- "$manifest"' EXIT
flake-plan-runner --flake . --plan "$XO_NIXPKG_PUBLISH_PLAN" --manifest "$manifest"
mapfile -t package_paths < <(jq -er '.results[].outputs[]' "$manifest")

if [[ ${#package_paths[@]} -ne 2 ]]; then
  printf 'Expected two final package paths, found %s\n' "${#package_paths[@]}" >&2
  exit 1
fi

cachix push xen-orchestra-ce "${package_paths[@]}"
