#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${CACHIX_AUTH_TOKEN:?CACHIX_AUTH_TOKEN must be set}"
: "${XO_NIXPKG_CACHIX_CACHE_NAME:?XO_NIXPKG_CACHIX_CACHE_NAME must be set}"
: "${PREPARED_CI_WORKFLOW:?PREPARED_CI_WORKFLOW must be set}"

publish_plan=$(mktemp)
evidence_dir=${XO_NIXPKG_CI_EVIDENCE:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/xo-nixpkg-ci-evidence}
mkdir -p "$evidence_dir"
rm -f -- "$evidence_dir/publication.json" "$evidence_dir/publication-timings.json"
manifest=$evidence_dir/publication.json
trap 'rm -f -- "$publish_plan"' EXIT
jq -er '
  select(
    .schemaVersion == 2 and
    .jobs.publish.enabled == true
  ) |
  .jobs.publish.plan
' <<<"$PREPARED_CI_WORKFLOW" >"$publish_plan"

flake-plan-runner --flake . --plan-file "$publish_plan" --manifest "$manifest" --timings "$evidence_dir/publication-timings.json"
mapfile -t package_paths < <(jq -er '.results[].outputs[]' "$manifest")

if [[ ${#package_paths[@]} -lt 1 ]]; then
  printf 'Expected at least one final package path\n' >&2
  exit 1
fi

cachix push "$XO_NIXPKG_CACHIX_CACHE_NAME" "${package_paths[@]}"
