#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail

usage() {
  cat <<'EOF'
Usage: flake-plan-runner (--plan ATTRIBUTE | --plan-file FILE) [--flake REFERENCE] [--manifest FILE] [--timings FILE] [--jobs 1|2]

Evaluate or consume one schema-v2 CI plan, validate its contract, build every
declared attribute in an isolated child process, and materialize links only
after the complete plan succeeds.
EOF
}

flake_ref=.
plan_attribute=
input_plan_file=
manifest_file=
timings_file=
parallelism=1

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
    --plan-file)
      (($# >= 2)) || { usage >&2; exit 2; }
      input_plan_file=$2
      shift 2
      ;;
    --manifest)
      (($# >= 2)) || { usage >&2; exit 2; }
      manifest_file=$2
      shift 2
      ;;
    --timings)
      (($# >= 2)) || { usage >&2; exit 2; }
      timings_file=$2
      shift 2
      ;;
    --jobs)
      (($# >= 2)) && [[ $2 == 1 || $2 == 2 ]] || { usage >&2; exit 2; }
      parallelism=$2
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

if [[ -n $plan_attribute && -n $input_plan_file ]] ||
   [[ -z $plan_attribute && -z $input_plan_file ]]; then
  printf '%s\n' 'exactly one of --plan or --plan-file is required' >&2
  exit 2
fi

nix_bin=${FLAKE_PLAN_RUNNER_NIX:-nix}
link_root=${FLAKE_PLAN_LINK_ROOT:-$PWD}
temporary=$(mktemp -d "${TMPDIR:-/tmp}/flake-plan-runner.XXXXXX")
active_pids=()
cleanup() {
  if ((${#active_pids[@]})); then
    kill "${active_pids[@]}" 2>/dev/null || true
    wait "${active_pids[@]}" 2>/dev/null || true
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
plan_json=$temporary/plan.json
results_jsonl=$temporary/results.jsonl
manifest_json=$temporary/manifest.json
timings_jsonl=$temporary/timings.jsonl

if [[ -n $input_plan_file ]]; then
  cp -- "$input_plan_file" "$plan_json"
  plan_source=$input_plan_file
else
  if ! "$nix_bin" eval --accept-flake-config --no-write-lock-file --json \
    "$flake_ref#$plan_attribute" >"$plan_json"; then
    printf 'Could not evaluate CI plan %s#%s\n' "$flake_ref" "$plan_attribute" >&2
    exit 1
  fi
  plan_source="$flake_ref#$plan_attribute"
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
  printf 'CI plan %s violates schema version 2\n' "$plan_source" >&2
  exit 1
fi

plan_name=$(jq -r .name "$plan_json")
failure_count=0
target_count=0

build_target() {
  trap - EXIT
  local target_name=$1 target_attribute=$2 target_link=$3 index=$4 build_pid=
  local outputs_file=$temporary/outputs-$index target_started target_elapsed status
  trap 'if [[ -n $build_pid ]]; then kill "$build_pid" 2>/dev/null || true; wait "$build_pid" 2>/dev/null || true; fi; exit 143' TERM INT
  printf 'Building %s (%s#%s)\n' "$target_name" "$flake_ref" "$target_attribute"
  target_started=$(date +%s)
  "$nix_bin" build --accept-flake-config --no-write-lock-file --no-link \
    --print-build-logs --print-out-paths "$flake_ref#$target_attribute" >"$outputs_file" &
  build_pid=$!
  if wait "$build_pid"; then
    status=success
  else
    status=failure
    : >"$outputs_file"
  fi
  build_pid=
  trap - TERM INT
  target_elapsed=$(( $(date +%s) - target_started ))
  jq -n --arg name "$target_name" --arg attribute "$target_attribute" \
    --arg status "$status" --argjson elapsedSeconds "$target_elapsed" \
    '{name:$name,attribute:$attribute,status:$status,elapsedSeconds:$elapsedSeconds}' \
    >"$temporary/timing-$index.json"
  jq -Rn \
    --arg name "$target_name" \
    --arg attribute "$target_attribute" \
    --arg link "$target_link" \
    --arg status "$status" \
    '[inputs | select(length > 0)] as $outputs |
      {name:$name,attribute:$attribute,status:$status,outputs:$outputs} +
      (if $link == "" then {} else {link:$link} end)' \
    <"$outputs_file" >"$temporary/result-$index.json"
}

wait_for_worker() {
  local completed='' pid
  local -a remaining=()
  # Refill whichever slot finishes first. Bash may already have reaped a very
  # short job before wait -n sees it; explicitly wait one recorded PID then.
  wait -n -p completed "${active_pids[@]}" 2>/dev/null || true
  if [[ -z ${completed:-} ]]; then
    completed=${active_pids[0]}
    wait "$completed" 2>/dev/null || true
  fi
  for pid in "${active_pids[@]}"; do
    [[ $pid == "$completed" ]] || remaining+=("$pid")
  done
  active_pids=("${remaining[@]}")
}

while IFS=$'\t' read -r target_name target_attribute target_link; do
  ((target_count += 1))
  build_target "$target_name" "$target_attribute" "$target_link" "$target_count" &
  active_pids+=("$!")
  if ((${#active_pids[@]} >= parallelism)); then
    wait_for_worker
  fi
done < <(jq -r '.targets[] | [.name, .attribute, (.link // "")] | @tsv' "$plan_json")

for pid in "${active_pids[@]}"; do wait "$pid" || true; done
active_pids=()
# Preserve plan ordering and complete diagnostics regardless of completion order.
for ((index = 1; index <= target_count; index++)); do
  [[ -s $temporary/result-$index.json && -s $temporary/timing-$index.json ]] || exit 1
  cat "$temporary/result-$index.json" >>"$results_jsonl"
  cat "$temporary/timing-$index.json" >>"$timings_jsonl"
  if [[ $(jq -r .status "$temporary/result-$index.json") != success ]]; then
    ((failure_count += 1))
  fi
done

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

if [[ -n $timings_file ]]; then
  mkdir -p "$(dirname "$timings_file")"
  jq -s --arg plan "$plan_name" '{schemaVersion:1,plan:$plan,results:.}' \
    "$timings_jsonl" >"$timings_file"
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
