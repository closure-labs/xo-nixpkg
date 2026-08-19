#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${CACHIX_AUTH_TOKEN:?CACHIX_AUTH_TOKEN must be set}"
: "${PREPARED_CI_WORKFLOW:?PREPARED_CI_WORKFLOW must be set}"

publish_plan=$(jq -er '
  select(
    .schemaVersion == 1 and
    .jobs.publish.enabled == true and
    (.gate.requiredJobs | index("publish") != null)
  ) |
  .jobs.publish.plan
' <<<"$PREPARED_CI_WORKFLOW")

manifest=$(mktemp)
trap 'rm -f -- "$manifest"' EXIT
flake-plan-runner --flake . --plan "$publish_plan" --manifest "$manifest"
mapfile -t package_paths < <(jq -er '.results[].outputs[]' "$manifest")

if [[ ${#package_paths[@]} -ne 2 ]]; then
  printf 'Expected two final package paths, found %s\n' "${#package_paths[@]}" >&2
  exit 1
fi

cachix push xen-orchestra-ce "${package_paths[@]}"
