#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=${XO_NIXPKG_SOURCE_ROOT:-$PWD}
flake_ref="git+file://$repo_root"
if [[ -z ${PREPARED_CI_WORKFLOW:-} ]]; then
  classify_ci=${XO_NIXPKG_CLASSIFY_CI_COMMAND:-xo-nixpkg-classify-ci}
  PREPARED_CI_WORKFLOW=$("$classify_ci")
fi
validation_plan=$(mktemp)
trap 'rm -f -- "$validation_plan"' EXIT
jq -er '
  select(
    .schemaVersion == 2 and
    .jobs.validate.enabled == true
  ) |
  .jobs.validate.plan
' <<<"$PREPARED_CI_WORKFLOW" >"$validation_plan"

nix flake check \
  --accept-flake-config \
  --no-build \
  --no-write-lock-file \
  --print-build-logs \
  "$flake_ref" \
  "$@"

exec flake-plan-runner \
  --flake "$flake_ref" \
  --plan-file "$validation_plan"
