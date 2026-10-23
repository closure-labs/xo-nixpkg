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
preflight_plan=$(mktemp)
runtime_plan=$(mktemp)
evidence_dir=${XO_NIXPKG_CI_EVIDENCE:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/xo-nixpkg-ci-evidence}
mkdir -p "$evidence_dir"
rm -f -- "$evidence_dir/preflight.json" "$evidence_dir/preflight-timings.json" \
  "$evidence_dir/runtime.json" "$evidence_dir/runtime-timings.json"
contract=${XO_NIXPKG_CLASSIFIER_CONTRACT:-$repo_root/ci/classifier.json}
if [[ ${XO_NIXPKG_FORCE_FULL_VALIDATION:-false} == true ]]; then
  PREPARED_CI_WORKFLOW=$(jq -cn --slurpfile contract "$contract" '
    {schemaVersion:2,jobs:{validate:{enabled:true,plan:{schemaVersion:2,
     name:"xo-nixpkg-validation-bootstrap",targets:[$contract[0].validationTargets[] | del(.requires)]}}}}')
fi
trap 'rm -f -- "$validation_plan" "$preflight_plan" "$runtime_plan"' EXIT
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

# All selected inexpensive contracts must pass before runtime compilation.
# The full runtime/VM/supply plan remains authoritative after this prerequisite.
jq --slurpfile contract "$contract" '
  .name += "-preflight" |
  .targets |= map(select(.name as $name | $contract[0].preflightTargets | index($name)))
' "$validation_plan" >"$preflight_plan"
jq --slurpfile contract "$contract" '
  .name += "-runtime" |
  .targets |= map(select(.name as $name | $contract[0].preflightTargets | index($name) | not))
' "$validation_plan" >"$runtime_plan"
if jq -e '.targets | length > 0' "$preflight_plan" >/dev/null; then
  flake-plan-runner --flake "$flake_ref" --plan-file "$preflight_plan" \
    --manifest "$evidence_dir/preflight.json" --timings "$evidence_dir/preflight-timings.json"
fi
if jq -e '.targets | length > 0' "$runtime_plan" >/dev/null; then
  flake-plan-runner --flake "$flake_ref" --plan-file "$runtime_plan" \
    --manifest "$evidence_dir/runtime.json" --timings "$evidence_dir/runtime-timings.json" \
    --jobs "${XO_NIXPKG_BUILD_JOBS:-1}"
fi
