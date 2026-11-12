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
    echo 'No current candidate: awaiting successful qualification; no evidence authority claimed.'
    exit 0
  fi
fi
if [[ -n ${QUALIFICATION_ATTEMPT:-} ]]; then
  [[ $QUALIFICATION_ATTEMPT =~ ^[1-9][0-9]{0,9}$ ]]
fi
selected=$(jq -ce --arg attempt "${QUALIFICATION_ATTEMPT:-}" --arg repo "$GITHUB_REPOSITORY" --arg requested "${QUALIFICATION_RUN:-}" '
  select(.repository.full_name == $repo and .head_repository.full_name == $repo and
    .path == ".github/workflows/qualification.yml" and .head_branch == "main" and
    .status == "completed" and .conclusion == "success" and
    (.event == "push" or .event == "schedule" or .event == "workflow_dispatch") and
    (.id | type == "number" and . > 0 and floor == .) and
    (.run_attempt | type == "number" and . > 0 and floor == .) and
    (.head_sha | test("^[0-9a-f]{40}$")) and
    (.created_at | test("^[0-9]{4}(-[0-9]{2}){2}T[0-9]{2}(:[0-9]{2}){2}Z$")) and
    ($requested == "" or (.id | tostring) == $requested) and
    ($attempt == "" or (.run_attempt | tostring) == $attempt))
' <<<"$selected")
run_id=$(jq -r .id <<<"$selected")
attempt=$(jq -r .run_attempt <<<"$selected")
created_at=$(jq -r .created_at <<<"$selected")

# Stable workflow run-names expose the requested input identity in authenticated
# Actions metadata. Never infer dispatch inputs from arbitrary commit messages.
workflow_state() {
  local workflow=$1 title=$2 alternate_title=${3:-} values state count page completed=false
  for page in {1..10}; do
    values=$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/$workflow/runs?branch=main&event=workflow_dispatch&created=%3E%3D$created_at&per_page=100&page=$page") || return
    state=$(jq -er --arg repo "$GITHUB_REPOSITORY" --arg path ".github/workflows/$workflow" \
      --arg title "$title" --arg alternate "$alternate_title" --arg workflow "$workflow" '
    .workflow_runs |
    if type != "array" or length > 100 then error("Invalid dispatch discovery") else . end |
    map(select(.repository.full_name == $repo and .head_repository.full_name == $repo and
      .path == $path and .head_branch == "main" and .event == "workflow_dispatch" and
      (.display_title == $title or ($alternate != "" and .display_title == $alternate)) and
      (.head_sha | test("^[0-9a-f]{40}$")))) |
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

# Automatic delivery is rolling-only. Both purposes include the same immutable
# cache/handoff work, so an exact active or successful release also suppresses
# duplicate rolling delivery. This scheduling fact never authorizes a write.
# Versioned tags/releases remain an explicit publish.yml purpose=release action.
# Active exact-run work is scheduling metadata and needs no packet download.
publication_state=$(workflow_state publish.yml "Publish rolling qualification $run_id attempt $attempt" "Publish release qualification $run_id attempt $attempt")
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
  observation_state=$(jq -er '.status | select(. == "current" or . == "expired" or . == "unretained" or . == "awaiting-current-evidence")' <<<"$observation")
  if [[ $observation_state == awaiting-current-evidence ]]; then
    printf '%s\n' "$observation"
    exit 0
  elif [[ $observation_state == current ]]; then
    printf '%s\n' "$observation"
    exit 0
  elif [[ $observation_state == expired ]]; then
    gh workflow run qualification.yml --repo "$GITHUB_REPOSITORY" --ref main \
      -f qualification_run="$run_id" -f qualification_attempt="$attempt"
    printf '%s\n' "$observation"
    exit 0
  fi
fi
# Transport observations are not receipts or authority. Keep only fixed fields;
# best-effort diagnostic I/O must never change the evidence/authority outcome.
transport_observation() {
  local phase=$1 transport=$2 outcome=$3 code=$4 seconds=$5
  printf 'Evidence transport: phase=%s transport=%s outcome=%s exit=%s seconds=%s\n' \
    "$phase" "$transport" "$outcome" "$code" "$seconds" >&2
  if [[ -n ${RUNNER_TEMP:-} ]]; then
    if ! jq -cn --arg phase "$phase" --arg transport "$transport" --arg outcome "$outcome" \
      --argjson exitCode "$code" --argjson seconds "$seconds" \
      --argjson run "$run_id" --argjson attempt "$attempt" \
      --argjson artifact "${artifact:-null}" \
      '{schema: 1, authorityClaim: false, phase: $phase, transport: $transport,
        outcome: $outcome, exitCode: $exitCode, elapsedSeconds: $seconds,
        runId: $run, runAttempt: $attempt, artifact: $artifact}' \
      >>"$RUNNER_TEMP/reconciliation-transport.jsonl"; then
      echo 'Unable to retain transport observation; evidence checks are unchanged.' >&2
    fi
  fi
}

# The hosted workflow uses the official streaming/retrying artifact action.
# Select one full product artifact, never inventories or a different attempt.
# The name-filtered catalog must be complete and unambiguous. Metadata is only
# transport selection: resume repeats producer identity and all evidence gates.
if [[ ${XO_NIXPKG_RECONCILE_PLAN_ONLY:-false} == true ]]; then
  : "${GITHUB_OUTPUT:?}"
  started=$SECONDS
  catalog_exit=0
  catalog=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id/artifacts?name=qualified-products-$run_id-$attempt&per_page=100") || catalog_exit=$?
  if (( catalog_exit != 0 )); then
    transport_observation catalog actions-artifact failure "$catalog_exit" "$((SECONDS - started))"
    exit "$catalog_exit"
  fi
  artifact=$(jq -c --arg name "qualified-products-$run_id-$attempt" --argjson run "$run_id" '
    if (.artifacts | type) != "array" or .total_count != (.artifacts | length) or .total_count > 1
      then error("Incomplete or ambiguous exact artifact catalog")
    elif .total_count == 0 then null
    else .artifacts[0] |
      if .name != $name or .workflow_run.id != $run or
        (.id | type != "number" or . <= 0 or floor != .) or
        (.size_in_bytes | type != "number" or . < 0 or floor != .) or
        (.expired | type != "boolean")
      then error("Invalid exact artifact metadata")
      else {id, sizeBytes: .size_in_bytes, expired} end
    end' <<<"$catalog") || {
      transport_observation catalog actions-artifact invalid-metadata 1 "$((SECONDS - started))"
      exit 1
    }
  artifact_id=''
  if [[ $artifact == null ]]; then
    artifact_state=missing
  elif [[ $(jq -r .expired <<<"$artifact") == true ]]; then
    artifact_state=expired
  else
    artifact_state=available
    artifact_id=$(jq -r .id <<<"$artifact")
  fi
  transport_observation catalog actions-artifact "$artifact_state" 0 "$((SECONDS - started))"
  printf 'run_id=%s\nattempt=%s\nartifact_id=%s\n' "$run_id" "$attempt" "$artifact_id" >>"$GITHUB_OUTPUT"
  exit 0
fi

started=$SECONDS
download_exit=0
if [[ ${XO_NIXPKG_RECONCILE_DOWNLOAD_OUTCOME+set} == set ]]; then
  # An action failure (including digest mismatch) must never admit partial bytes.
  # Only the fixed hosted staging path is handed over; producer/attestation
  # verification below remains mandatory even after successful SDK transport.
  case "$XO_NIXPKG_RECONCILE_DOWNLOAD_OUTCOME" in
    success)
      : "${XO_NIXPKG_RECONCILE_DOWNLOADED_EVIDENCE:?}"
      [[ -d $XO_NIXPKG_RECONCILE_DOWNLOADED_EVIDENCE && ! -L $XO_NIXPKG_RECONCILE_DOWNLOADED_EVIDENCE ]]
      # Use the full staged tree in place; do not copy gigabytes across mounts.
      export XO_NIXPKG_EVIDENCE="$XO_NIXPKG_RECONCILE_DOWNLOADED_EVIDENCE"
      ;;
    failure|skipped) download_exit=1 ;;
    *) echo 'Invalid hosted artifact outcome.' >&2; exit 1 ;;
  esac
  # Actions exposes an outcome, not the SDK process exit code. Do not invent it
  # or count staging time as download time; the workflow step owns its timing.
  transport_observation download actions-artifact "$XO_NIXPKG_RECONCILE_DOWNLOAD_OUTCOME" null null
else
  # Preserve bounded standalone CLI use, now recording its actual failure code.
  timeout --signal=TERM --kill-after=10s 600s gh run download "$run_id" --repo "$GITHUB_REPOSITORY" --name "qualified-products-$run_id-$attempt" --dir "$XO_NIXPKG_EVIDENCE" || download_exit=$?
  outcome=success
  (( download_exit == 0 )) || outcome=failure
  transport_observation download gh-cli "$outcome" "$download_exit" "$((SECONDS - started))"
fi
if (( download_exit != 0 )); then
  rm -rf -- "$XO_NIXPKG_EVIDENCE"
  printf '%s' "$REGISTRY_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
  export QUALIFICATION_RUN="$run_id" QUALIFICATION_ATTEMPT="$attempt"
  started=$SECONDS
  recovery_exit=0
  python3 "$XO_NIXPKG_RETAINED_FETCH_SOURCE" || recovery_exit=$?
  outcome=success
  (( recovery_exit == 0 )) || outcome=failure
  transport_observation retained-recovery immutable-packet "$outcome" "$recovery_exit" "$((SECONDS - started))"
  (( recovery_exit == 0 )) || exit "$recovery_exit"
fi
jq -e --argjson run "$run_id" --argjson attempt "$attempt" \
  '.producer.runId == $run and .producer.runAttempt == $attempt' \
  "$XO_NIXPKG_EVIDENCE/scans.json" >/dev/null
# Authenticate scans AND product before treating policy mismatch as scheduling
# debt. This also validates Actions-download evidence, not just retained packets.
observation=$(XO_NIXPKG_INSPECT_LOCAL_EVIDENCE=true QUALIFICATION_RUN="$run_id" QUALIFICATION_ATTEMPT="$attempt" QUALIFICATION_SOURCE_SHA="$(jq -r .head_sha <<<"$selected")" xo-nixpkg-inspect-qualification)
observation_state=$(jq -er '.status | select(. == "current" or . == "expired" or . == "awaiting-current-evidence")' <<<"$observation")
if [[ $observation_state == awaiting-current-evidence ]]; then
  printf '%s\n' "$observation"
  exit 0
fi
if [[ $observation_state == expired ]]; then
  refresh_state=$(workflow_state qualification.yml "Refresh qualification $run_id attempt $attempt")
  if [[ $refresh_state != active ]]; then
    gh workflow run qualification.yml --repo "$GITHUB_REPOSITORY" --ref main \
      -f qualification_run="$run_id" -f qualification_attempt="$attempt"
  fi
  exit 0
fi
publication_state=$(workflow_state publish.yml "Publish rolling qualification $run_id attempt $attempt" "Publish release qualification $run_id attempt $attempt")
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
  --scans "$XO_NIXPKG_EVIDENCE/scans.json" --product "$XO_NIXPKG_EVIDENCE/product.json" --purpose rolling; then
  gh workflow run publish.yml --repo "$GITHUB_REPOSITORY" --ref main \
    -f qualification_run="$run_id" -f qualification_attempt="$attempt" -f purpose=rolling
fi
