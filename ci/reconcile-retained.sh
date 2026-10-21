#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${GITHUB_REPOSITORY:?}"
: "${REGISTRY_TOKEN:?}"

# Reconciliation schedules work; the decision leaves and publisher authenticate
# evidence and repeat live authority. Historical products remain explicit work,
# rather than being resurrected on every hourly tick.
if [[ -n ${QUALIFICATION_RUN:-} ]]; then
  [[ $QUALIFICATION_RUN =~ ^[1-9][0-9]{0,19}$ ]]
  selected=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$QUALIFICATION_RUN")
else
  discovered=$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/qualification.yml/runs?branch=main&status=success&per_page=1")
  selected=$(jq -c '.workflow_runs | if type != "array" or length > 1 then error("Invalid qualification discovery") else .[0] end' <<<"$discovered")
  if [[ $selected == null ]]; then
    echo 'No successful qualification is available.'
    exit 0
  fi
fi
selected=$(jq -ce --arg repo "$GITHUB_REPOSITORY" --arg requested "${QUALIFICATION_RUN:-}" '
  select(.repository.full_name == $repo and .head_repository.full_name == $repo and
    .path == ".github/workflows/qualification.yml" and .head_branch == "main" and
    .status == "completed" and .conclusion == "success" and
    (.event == "push" or .event == "schedule" or .event == "workflow_dispatch") and
    (.id | type == "number" and . > 0 and floor == .) and
    (.run_attempt | type == "number" and . > 0 and floor == .) and
    (.head_sha | test("^[0-9a-f]{40}$")) and
    (.created_at | test("^[0-9]{4}(-[0-9]{2}){2}T[0-9]{2}(:[0-9]{2}){2}Z$")) and
    ($requested == "" or (.id | tostring) == $requested))
' <<<"$selected")
run_id=$(jq -r .id <<<"$selected")
attempt=$(jq -r .run_attempt <<<"$selected")
created_at=$(jq -r .created_at <<<"$selected")

# Stable workflow run-names expose the requested input identity in authenticated
# Actions metadata. Never infer dispatch inputs from arbitrary commit messages.
workflow_state() {
  local workflow=$1 title=$2 values state count page completed=false
  for page in {1..10}; do
    values=$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/$workflow/runs?branch=main&event=workflow_dispatch&created=%3E%3D$created_at&per_page=100&page=$page") || return
    state=$(jq -er --arg repo "$GITHUB_REPOSITORY" --arg path ".github/workflows/$workflow" \
      --arg title "$title" --arg workflow "$workflow" '
    .workflow_runs |
    if type != "array" or length > 100 then error("Invalid dispatch discovery") else . end |
    map(select(.repository.full_name == $repo and .head_repository.full_name == $repo and
      .path == $path and .head_branch == "main" and .event == "workflow_dispatch" and
      .display_title == $title and (.head_sha | test("^[0-9a-f]{40}$")))) |
    if any(.status as $s | ["queued", "in_progress", "waiting", "pending", "requested"] | index($s)) then "active"
    elif $workflow == "publish.yml" and any(.status == "completed" and .conclusion == "success") then "complete"
    else "absent" end
    ' <<<"$values") || return
    if [[ $state == active ]]; then echo active; return; fi
    [[ $state == complete ]] && completed=true
    count=$(jq '.workflow_runs | length' <<<"$values")
    if (( count < 100 )); then
      if [[ $completed == true ]]; then echo complete; else echo absent; fi
      return
    fi
  done
  echo 'Dispatch discovery exceeded 1000 records; use explicit publication recovery.' >&2
  return 1
}

# Active exact-run work is scheduling metadata and needs no packet download.
publication_state=$(workflow_state publish.yml "Publish release qualification $run_id attempt $attempt")
if [[ $publication_state == active ]]; then
  printf 'Qualification %s publication is active.\n' "$run_id"
  exit 0
fi
refresh_state=$(workflow_state qualification.yml "Refresh qualification $run_id attempt $attempt")
if [[ $refresh_state == active ]]; then
  printf 'Qualification %s refresh is active.\n' "$run_id"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf -- "$work"; oras logout ghcr.io >/dev/null 2>&1 || true' EXIT
export XO_NIXPKG_EVIDENCE="$work/$run_id"
if [[ $publication_state == complete ]]; then
  # Historical success suppresses bulk work only after current immutable
  # observation expiry has been inspected. This is never an admission cache.
  printf '%s' "$REGISTRY_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
  observation=$(QUALIFICATION_RUN="$run_id" QUALIFICATION_ATTEMPT="$attempt" QUALIFICATION_SOURCE_SHA="$(jq -r .head_sha <<<"$selected")" xo-nixpkg-inspect-qualification)
  observation_state=$(jq -er '.status | select(. == "current" or . == "expired" or . == "unretained")' <<<"$observation")
  if [[ $observation_state == current ]]; then
    printf '%s\n' "$observation"
    exit 0
  elif [[ $observation_state == expired ]]; then
    gh workflow run qualification.yml --repo "$GITHUB_REPOSITORY" --ref main \
      -f qualification_run="$run_id" -f qualification_attempt="$attempt"
    printf '%s\n' "$observation"
    exit 0
  fi
fi
# Bound optional artifact transport before the existing authenticated recovery path.
if ! timeout --signal=TERM --kill-after=10s 600s gh run download "$run_id" --repo "$GITHUB_REPOSITORY" --name "qualified-products-$run_id-$attempt" --dir "$XO_NIXPKG_EVIDENCE"; then
  rm -rf -- "$XO_NIXPKG_EVIDENCE"
  printf '%s' "$REGISTRY_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
  export QUALIFICATION_RUN="$run_id" QUALIFICATION_ATTEMPT="$attempt"
  python3 "$XO_NIXPKG_RETAINED_FETCH_SOURCE"
fi
jq -e --argjson run "$run_id" --argjson attempt "$attempt" \
  '.producer.runId == $run and .producer.runAttempt == $attempt' \
  "$XO_NIXPKG_EVIDENCE/scans.json" >/dev/null
if [[ $(date -u +%s) -ge $(date -u --date="$(jq -er .expiresAt "$XO_NIXPKG_EVIDENCE/scans.json")" +%s) ]]; then
  refresh_state=$(workflow_state qualification.yml "Refresh qualification $run_id attempt $attempt")
  if [[ $refresh_state != active ]]; then
    gh workflow run qualification.yml --repo "$GITHUB_REPOSITORY" --ref main \
      -f qualification_run="$run_id" -f qualification_attempt="$attempt"
  fi
  exit 0
fi
publication_state=$(workflow_state publish.yml "Publish release qualification $run_id attempt $attempt")
if [[ $publication_state != absent ]]; then
  printf 'Qualification %s publication is %s.\n' "$run_id" "$publication_state"
  exit 0
fi
printf '%s' "$REGISTRY_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
xo-nixpkg-decision-reconcile --config ci/decision-policy.json \
  --scans "$XO_NIXPKG_EVIDENCE/scans.json" --product "$XO_NIXPKG_EVIDENCE/product.json" \
  --directory "$XO_NIXPKG_EVIDENCE" --kind security-findings
xo-nixpkg-decision-reconcile --config ci/decision-policy.json \
  --scans "$XO_NIXPKG_EVIDENCE/scans.json" --product "$XO_NIXPKG_EVIDENCE/product.json" \
  --directory "$XO_NIXPKG_EVIDENCE" --kind release-product
# The publisher repeats every live gate and does not trust scheduler state.
if xo-nixpkg-decision-publication --config ci/decision-policy.json \
  --scans "$XO_NIXPKG_EVIDENCE/scans.json" --product "$XO_NIXPKG_EVIDENCE/product.json" --purpose release; then
  gh workflow run publish.yml --repo "$GITHUB_REPOSITORY" --ref main \
    -f qualification_run="$run_id" -f qualification_attempt="$attempt" -f purpose=release
fi
