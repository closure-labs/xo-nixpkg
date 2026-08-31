#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${CACHIX_AUTH_TOKEN:?CACHIX_AUTH_TOKEN must be set}"
: "${XO_NIXPKG_CACHIX_CACHE_NAME:?XO_NIXPKG_CACHIX_CACHE_NAME must be set}"
: "${PREPARED_CI_WORKFLOW:?PREPARED_CI_WORKFLOW must be set}"

publish_plan=$(mktemp)
manifest=$(mktemp)
trap 'rm -f -- "$publish_plan" "$manifest"' EXIT
jq -er '
  select(
    .schemaVersion == 2 and
    .jobs.publish.enabled == true
  ) |
  .jobs.publish.plan
' <<<"$PREPARED_CI_WORKFLOW" >"$publish_plan"

flake-plan-runner --flake . --plan-file "$publish_plan" --manifest "$manifest"
mapfile -t package_paths < <(jq -er '.results[].outputs[]' "$manifest")

if [[ ${#package_paths[@]} -lt 1 ]]; then
  printf 'Expected at least one final package path\n' >&2
  exit 1
fi

cachix push "$XO_NIXPKG_CACHIX_CACHE_NAME" "${package_paths[@]}"
