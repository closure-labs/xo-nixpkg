#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail

usage() {
  cat <<'EOF'
Usage: flake-plan-runner --plan ATTRIBUTE [--flake REFERENCE] [--manifest FILE]

Evaluate one schema-v2 CI plan, validate its contract, build every declared
attribute in an isolated child process, and materialize links only after the
complete plan succeeds.
EOF
}

flake_ref=.
plan_attribute=
manifest_file=

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
    --manifest)
      (($# >= 2)) || { usage >&2; exit 2; }
      manifest_file=$2
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

[[ -n $plan_attribute ]] || { printf '%s\n' '--plan is required' >&2; exit 2; }

nix_bin=${FLAKE_PLAN_RUNNER_NIX:-nix}
link_root=${FLAKE_PLAN_LINK_ROOT:-$PWD}
temporary=$(mktemp -d "${TMPDIR:-/tmp}/flake-plan-runner.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
plan_json=$temporary/plan.json
results_jsonl=$temporary/results.jsonl
manifest_json=$temporary/manifest.json

if ! "$nix_bin" eval --accept-flake-config --no-write-lock-file --json \
  "$flake_ref#$plan_attribute" >"$plan_json"; then
  printf 'Could not evaluate CI plan %s#%s\n' "$flake_ref" "$plan_attribute" >&2
  exit 1
fi

if ! jq -e '
  type == "object" and
  (keys | sort) == ["name", "schemaVersion", "targets"] and
  .schemaVersion == 2 and
  (.name | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]*$")) and
  (.targets | type == "array" and length > 0) and
  all(.targets[];
    type == "object" and
    ((keys | sort) == ["attribute", "name"] or
     (keys | sort) == ["attribute", "link", "name"]) and
    (.name | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]*$")) and
    (.attribute | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._+-]*$") and
      (contains("..") | not)) and
    ((has("link") | not) or
      (.link | type == "string" and length > 0 and startswith("/") == false and
        test("^[A-Za-z0-9._+-][A-Za-z0-9._+/-]*$") and contains("..") == false))) and
  ([.targets[].name] | length == (unique | length)) and
  ([.targets[].attribute] | length == (unique | length)) and
  ([.targets[] | select(has("link")) | .link] | length == (unique | length))
' "$plan_json" >/dev/null; then
  printf 'CI plan %s#%s violates schema version 2\n' "$flake_ref" "$plan_attribute" >&2
  exit 1
fi

plan_name=$(jq -r .name "$plan_json")
failure_count=0
target_count=0

while IFS=$'\t' read -r target_name target_attribute target_link; do
  ((target_count += 1))
  outputs_file=$temporary/outputs-$target_count
  printf 'Building %s (%s#%s)\n' "$target_name" "$flake_ref" "$target_attribute"
  if "$nix_bin" build --accept-flake-config --no-write-lock-file --no-link \
    --print-build-logs --print-out-paths "$flake_ref#$target_attribute" >"$outputs_file"; then
    status=success
  else
    status=failure
    ((failure_count += 1))
    : >"$outputs_file"
  fi
  jq -Rn \
    --arg name "$target_name" \
    --arg attribute "$target_attribute" \
    --arg link "$target_link" \
    --arg status "$status" \
    '[inputs | select(length > 0)] as $outputs |
      {name:$name,attribute:$attribute,status:$status,outputs:$outputs} +
      (if $link == "" then {} else {link:$link} end)' \
    <"$outputs_file" >>"$results_jsonl"
done < <(jq -r '.targets[] | [.name, .attribute, (.link // "")] | @tsv' "$plan_json")

jq -s \
  --arg plan "$plan_name" \
  --arg flake "$flake_ref" \
  --argjson targetCount "$target_count" \
  --argjson failureCount "$failure_count" \
  '{schemaVersion:2,plan:$plan,flake:$flake,targetCount:$targetCount,
    failureCount:$failureCount,results:.}' \
  "$results_jsonl" >"$manifest_json"

if [[ -n $manifest_file ]]; then
  install -Dm0644 "$manifest_json" "$manifest_file"
fi

if ((failure_count > 0)); then
  printf 'CI plan %s failed for %s of %s attributes\n' \
    "$plan_name" "$failure_count" "$target_count" >&2
  exit 1
fi

while IFS=$'\t' read -r target_name target_link output_count output_path; do
  [[ -n $target_link ]] || continue
  if [[ $output_count != 1 ]]; then
    printf 'Target %s links require exactly one output, found %s\n' \
      "$target_name" "$output_count" >&2
    exit 1
  fi
  destination=$link_root/$target_link
  if [[ -e $destination && ! -L $destination ]]; then
    printf 'Refusing to replace non-symlink result path: %s\n' "$destination" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$destination")"
  temporary_link=$destination.tmp.$$
  ln -s "$output_path" "$temporary_link"
  mv -Tf "$temporary_link" "$destination"
done < <(jq -r '.results[] | select(has("link")) |
  [.name,.link,(.outputs|length),(.outputs[0] // "")] | @tsv' "$manifest_json")

printf 'CI plan %s built %s attributes successfully\n' "$plan_name" "$target_count"
