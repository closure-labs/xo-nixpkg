#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail

usage() {
  cat <<'EOF'
Usage: flake-attribute-validator --plan ATTRIBUTE [--flake REFERENCE] [--summary FILE]

Evaluate one pure flake plan, validate its JSON contract, and build every
declared attribute in an independent child process while collecting failures.
EOF
}

flake_ref=.
plan_attribute=
summary_file=

while (($# > 0)); do
  case "$1" in
    --flake)
      (($# >= 2)) || { usage >&2; exit 2; }
      flake_ref=$2
      shift 2
      ;;
    --plan)
      (($# >= 2)) || { usage >&2; exit 2; }
      plan_attribute=$2
      shift 2
      ;;
    --summary)
      (($# >= 2)) || { usage >&2; exit 2; }
      summary_file=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z $plan_attribute ]]; then
  printf '%s\n' '--plan is required' >&2
  usage >&2
  exit 2
fi

nix_bin=${FLAKE_ATTRIBUTE_VALIDATOR_NIX:-nix}
temporary=$(mktemp -d "${TMPDIR:-/tmp}/flake-attribute-validator.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
plan_json=$temporary/plan.json
results_jsonl=$temporary/results.jsonl
summary_json=$temporary/summary.json

if ! "$nix_bin" eval \
  --accept-flake-config \
  --no-write-lock-file \
  --json \
  "$flake_ref#$plan_attribute" >"$plan_json"; then
  printf 'Could not evaluate CI plan %s#%s\n' "$flake_ref" "$plan_attribute" >&2
  exit 1
fi

if ! jq -e '
  type == "object" and
  (keys | sort) == ["name", "schemaVersion", "targets"] and
  .schemaVersion == 1 and
  (.name | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]*$")) and
  (.targets | type == "array" and length > 0) and
  all(.targets[];
    type == "object" and
    (keys | sort) == ["attribute", "name"] and
    (.name | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]*$")) and
    (.attribute |
      type == "string" and
      test("^[A-Za-z0-9][A-Za-z0-9._+-]*$") and
      (contains("..") | not))) and
  ([.targets[].name] | length == (unique | length)) and
  ([.targets[].attribute] | length == (unique | length))
' "$plan_json" >/dev/null; then
  printf 'CI plan %s#%s violates schema version 1\n' "$flake_ref" "$plan_attribute" >&2
  exit 1
fi

plan_name=$(jq -r '.name' "$plan_json")
failure_count=0
target_count=0

while IFS=$'\t' read -r target_name target_attribute; do
  ((target_count += 1))
  printf 'Building %s (%s#%s)\n' "$target_name" "$flake_ref" "$target_attribute"
  if "$nix_bin" build \
    --accept-flake-config \
    --no-write-lock-file \
    --no-link \
    --print-build-logs \
    "$flake_ref#$target_attribute"; then
    status=success
  else
    status=failure
    ((failure_count += 1))
  fi
  jq -nc \
    --arg name "$target_name" \
    --arg attribute "$target_attribute" \
    --arg status "$status" \
    '{name: $name, attribute: $attribute, status: $status}' >>"$results_jsonl"
done < <(jq -r '.targets[] | [.name, .attribute] | @tsv' "$plan_json")

jq -s \
  --arg plan "$plan_name" \
  --arg flake "$flake_ref" \
  --argjson targetCount "$target_count" \
  --argjson failureCount "$failure_count" \
  '{
    schemaVersion: 1,
    plan: $plan,
    flake: $flake,
    targetCount: $targetCount,
    failureCount: $failureCount,
    results: .
  }' "$results_jsonl" >"$summary_json"

if [[ -n $summary_file ]]; then
  cp "$summary_json" "$summary_file"
fi

if ((failure_count > 0)); then
  printf 'CI plan %s failed for %s of %s attributes\n' \
    "$plan_name" "$failure_count" "$target_count" >&2
  exit 1
fi

printf 'CI plan %s built %s attributes successfully\n' "$plan_name" "$target_count"
