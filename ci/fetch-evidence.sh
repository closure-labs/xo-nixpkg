#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
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
if ! gh run download "$QUALIFICATION_RUN" --repo "$GITHUB_REPOSITORY" --name "qualified-products-$QUALIFICATION_RUN-$attempt" --dir "$XO_NIXPKG_EVIDENCE"; then
  rm -rf -- "$XO_NIXPKG_EVIDENCE"
  export QUALIFICATION_ATTEMPT="$attempt"
  printf '%s' "$REGISTRY_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
  trap 'oras logout ghcr.io >/dev/null 2>&1 || true' EXIT
  python3 "$XO_NIXPKG_RETAINED_FETCH_SOURCE"
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
