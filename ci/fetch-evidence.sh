#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
if [[ ${XO_NIXPKG_FETCH_BOUNDED:-false} != true ]]; then
  export XO_NIXPKG_FETCH_BOUNDED=true
  exec python3 "${XO_NIXPKG_OPERATIONS_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/operations.py}" --timeout 900 -- bash "$0" "$@"
fi
gh() {
  if [[ ${1:-} == api ]]; then
    python3 "${XO_NIXPKG_OPERATIONS_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/operations.py}" --timeout 30 -- gh "$@"
  else
    command gh "$@"
  fi
}
if [[ ${XO_NIXPKG_FETCH_FOR_RESCAN:-false} == true && -z ${QUALIFICATION_RUN:-} ]]; then
  QUALIFICATION_RUN=$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/qualification.yml/runs?branch=main&status=success&per_page=1" --jq '.workflow_runs[0].id')
fi
: "${QUALIFICATION_RUN:?}"
export QUALIFICATION_RUN
: "${GITHUB_REPOSITORY:?}"
: "${XO_NIXPKG_EVIDENCE:?}"
[[ $QUALIFICATION_RUN =~ ^[1-9][0-9]*$ ]]
run=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$QUALIFICATION_RUN")
jq -e --arg repo "$GITHUB_REPOSITORY" '.conclusion == "success" and .head_repository.full_name == $repo and .head_branch == "main" and (.event == "push" or .event == "schedule" or .event == "workflow_dispatch") and .path == ".github/workflows/qualification.yml"' <<<"$run" >/dev/null
attempt=$(jq -er .run_attempt <<<"$run")
[[ $attempt =~ ^[1-9][0-9]*$ ]]
if [[ -n ${QUALIFICATION_ATTEMPT:-} ]]; then
  [[ $QUALIFICATION_ATTEMPT =~ ^[1-9][0-9]*$ && $QUALIFICATION_ATTEMPT == "$attempt" ]]
fi
[[ ! -e $XO_NIXPKG_EVIDENCE ]]
# An admitted retained packet permits metadata-only inspection before bulk transfer.
metadata_ready=false
if [[ ${XO_NIXPKG_PUBLICATION_METADATA_ONLY:-false} == true ]]; then
  export QUALIFICATION_ATTEMPT="$attempt"
  registry_config=$(mktemp -d)
  export DOCKER_CONFIG="$registry_config"
  trap 'rm -rf -- "$registry_config"' EXIT
  printf '%s' "$REGISTRY_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
  metadata_status=0
  python3 "$XO_NIXPKG_RETAINED_FETCH_SOURCE" || metadata_status=$?
  oras logout ghcr.io >/dev/null
  if [[ $metadata_status == 0 ]]; then metadata_ready=true
  elif [[ $metadata_status != 4 ]]; then exit "$metadata_status"
  fi
fi
# Inventory-only refresh never downloads the closure artifact. Absence/expiry uses
# the existing authenticated retained packet's bounded inventory members only.
if [[ ${XO_NIXPKG_FETCH_FOR_RESCAN:-false} == true && ${XO_NIXPKG_FETCH_FULL_TRANSPORT:-false} != true ]]; then
  inventory_name="qualified-inventories-$QUALIFICATION_RUN-$attempt"
  catalog=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$QUALIFICATION_RUN/artifacts?per_page=100")
  jq -e '(.artifacts | type) == "array" and (.total_count | type) == "number" and .total_count == (.artifacts | length) and .total_count <= 100' <<<"$catalog" >/dev/null
  matches=$(jq -c --arg name "$inventory_name" '[.artifacts[] | select(.name == $name)]' <<<"$catalog")
  [[ $(jq length <<<"$matches") -le 1 ]]
  jq -e 'all(.[]; (.expired | type) == "boolean" and (.size_in_bytes | type) == "number" and .size_in_bytes > 0 and .size_in_bytes == (.size_in_bytes | floor))' <<<"$matches" >/dev/null
  if [[ $(jq length <<<"$matches") == 1 && $(jq -r '.[0].expired' <<<"$matches") == false ]]; then
    jq -e '.[0].size_in_bytes > 0 and .[0].size_in_bytes <= 536870912' <<<"$matches" >/dev/null
    timeout --signal=TERM --kill-after=10s 600s gh run download "$QUALIFICATION_RUN" --repo "$GITHUB_REPOSITORY" --name "$inventory_name" --dir "$XO_NIXPKG_EVIDENCE"
  else
    export QUALIFICATION_ATTEMPT="$attempt" XO_NIXPKG_RESCAN_INVENTORY_ONLY=true
    registry_config=$(mktemp -d)
    export DOCKER_CONFIG="$registry_config"
    trap 'rm -rf -- "$registry_config"' EXIT
    printf '%s' "$REGISTRY_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
    python3 "$XO_NIXPKG_RETAINED_FETCH_SOURCE"
    oras logout ghcr.io >/dev/null
  fi
else
  # Artifact transport/extraction may stall; retained recovery repeats authentication.
  if [[ $metadata_ready != true ]] && ! timeout --signal=TERM --kill-after=10s 600s gh run download "$QUALIFICATION_RUN" --repo "$GITHUB_REPOSITORY" --name "qualified-products-$QUALIFICATION_RUN-$attempt" --dir "$XO_NIXPKG_EVIDENCE"; then
    rm -rf -- "$XO_NIXPKG_EVIDENCE"
    export QUALIFICATION_ATTEMPT="$attempt"
    printf '%s' "$REGISTRY_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
    trap 'oras logout ghcr.io >/dev/null 2>&1 || true' EXIT
    python3 "$XO_NIXPKG_RETAINED_FETCH_SOURCE"
  fi
fi
# Bind the requested attempt before admission; a rerun of one run ID is a new
# scan producer and must not satisfy an older publication request.
jq -e --argjson run "$QUALIFICATION_RUN" --argjson attempt "$attempt" \
  '.producer.runId == $run and .producer.runAttempt == $attempt' \
  "$XO_NIXPKG_EVIDENCE/scans.json" >/dev/null
# Core re-verifies producer attestations, current policy and live human authority.
if [[ ${XO_NIXPKG_FETCH_FOR_RESCAN:-false} != true ]]; then
  xo-nixpkg-publication-gate
else
  python3 "$XO_NIXPKG_RESCAN_VERIFIER_SOURCE"
fi
