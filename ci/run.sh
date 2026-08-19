#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=${XO_NIXPKG_SOURCE_ROOT:-$PWD}
flake_ref="git+file://$repo_root"
if [[ -z ${PREPARED_CI_WORKFLOW:-} ]]; then
  prepare_ci=${XO_NIXPKG_PREPARE_CI_COMMAND:-xo-nixpkg-prepare-ci}
  PREPARED_CI_WORKFLOW=$("$prepare_ci")
fi
validation_plan=$(jq -er '
  select(
    .schemaVersion == 1 and
    .jobs.validate.enabled == true and
    (.gate.requiredJobs | index("validate") != null)
  ) |
  .jobs.validate.plan
' <<<"$PREPARED_CI_WORKFLOW")

nix flake check \
  --accept-flake-config \
  --no-build \
  --no-write-lock-file \
  --print-build-logs \
  "$flake_ref" \
  "$@"

exec flake-plan-runner \
  --flake "$flake_ref" \
  --plan "$validation_plan"
