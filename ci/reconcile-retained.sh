#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${GITHUB_REPOSITORY:?}"
: "${REGISTRY_TOKEN:?}"
printf '%s' "$REGISTRY_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
work=$(mktemp -d)
trap 'rm -rf -- "$work"; oras logout ghcr.io >/dev/null 2>&1 || true' EXIT
mapfile -t runs < <(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/qualification.yml/runs?branch=main&status=success&per_page=20" --jq '.workflow_runs[] | [.id,.run_attempt] | @tsv')
(( ${#runs[@]} > 0 ))
declare -A seen_products=()
for run in "${runs[@]}"; do
  IFS=$'\t' read -r run_id attempt <<<"$run"
  export XO_NIXPKG_EVIDENCE="$work/$run_id"
  if ! gh run download "$run_id" --repo "$GITHUB_REPOSITORY" --name "qualified-products-$run_id-$attempt" --dir "$XO_NIXPKG_EVIDENCE"; then
    rm -rf -- "$XO_NIXPKG_EVIDENCE"
    export QUALIFICATION_RUN="$run_id" QUALIFICATION_ATTEMPT="$attempt"
    python3 "$XO_NIXPKG_RETAINED_FETCH_SOURCE"
  fi
  product_hash=$(sha256sum "$XO_NIXPKG_EVIDENCE/product.json" | cut -d' ' -f1)
  if [[ -n ${seen_products[$product_hash]:-} ]]; then rm -rf -- "$XO_NIXPKG_EVIDENCE"; continue; fi
  seen_products[$product_hash]=true
  if [[ $(date -u +%s) -ge $(date -u --date="$(jq -er .expiresAt "$XO_NIXPKG_EVIDENCE/scans.json")" +%s) ]]; then
    gh workflow run qualification.yml --repo "$GITHUB_REPOSITORY" --ref main -f qualification_run="$run_id"
    rm -rf -- "$XO_NIXPKG_EVIDENCE"
    continue
  fi
  # Idempotent reconciliation retains immutable packet and exact product request.
  # An expired scan fails here and remains blocked for fresh qualification.
  xo-nixpkg-decision-reconcile --config ci/decision-policy.json \
    --scans "$XO_NIXPKG_EVIDENCE/scans.json" --product "$XO_NIXPKG_EVIDENCE/product.json" \
    --directory "$XO_NIXPKG_EVIDENCE" --kind security-findings
  xo-nixpkg-decision-reconcile --config ci/decision-policy.json \
    --scans "$XO_NIXPKG_EVIDENCE/scans.json" --product "$XO_NIXPKG_EVIDENCE/product.json" \
    --directory "$XO_NIXPKG_EVIDENCE" --kind release-product
  # Publication is requested separately after proposal reconciliation. The
  # publisher repeats every live gate and does not trust this workflow result.
  if xo-nixpkg-decision-publication --config ci/decision-policy.json \
    --scans "$XO_NIXPKG_EVIDENCE/scans.json" --product "$XO_NIXPKG_EVIDENCE/product.json" --purpose release; then
    gh workflow run publish.yml --repo "$GITHUB_REPOSITORY" --ref main \
      -f qualification_run="$run_id" -f purpose=release
  fi
  rm -rf -- "$XO_NIXPKG_EVIDENCE"
done
