#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=${XO_NIXPKG_SOURCE_ROOT:-$PWD}
contract=${XO_NIXPKG_CLASSIFIER_CONTRACT:-$repo_root/ci/classifier.json}
event_path=${GITHUB_EVENT_PATH:-}
event_name=${GITHUB_EVENT_NAME:-local}
event_ref=${GITHUB_REF:-local}
head_sha=${GITHUB_SHA:-$(git -C "$repo_root" rev-parse HEAD)}
output_file=${1:-}

jq -e '
  . as $contract |
  [.validationTargets[].name] as $validationNames |
  [.publicationTargets[].name] as $publicationNames |
  .schemaVersion == 1 and
  (.lifecycle.publish | keys | sort) == ["event", "ref"] and
  (.lifecycle.release | keys | sort) == ["event", "ref"] and
  (.validationTargets | type == "array" and length > 0) and
  (.publicationTargets | type == "array" and length > 0) and
  ($validationNames | length == (unique | length)) and
  ($publicationNames | length == (unique | length)) and
  all(.validationTargets[];
    (keys | sort) == ["attribute", "name", "requires"] and
    (.requires | type == "array") and
    all(.requires[]; . as $name | $validationNames | index($name))) and
  all(.publicationTargets[]; (keys | sort) == ["attribute", "name"]) and
  (.pathRules | type == "array" and length > 0) and
  all(.pathRules[];
    (keys | sort) == ["pattern", "publication", "validation"] and
    (.pattern | type == "string") and
    (. as $rule | try ("" | test($rule.pattern)) catch null) != null and
    all(.validation[]; . == "*" or (. as $name | $validationNames | index($name))) and
    all(.publication[]; . == "*" or (. as $name | $publicationNames | index($name))))
' "$contract" >/dev/null

declare -A validation_names=()
declare -A publication_names=()
classification_mode=full
classification_reason=event-does-not-classify-paths
classification_base=
changed_path_count=0
publication_changed_path_count=0

select_all() {
  local kind=$1 name
  while IFS= read -r name; do
    [[ -n $name ]] || continue
    if [[ $kind == validation ]]; then
      validation_names["$name"]=1
    else
      publication_names["$name"]=1
    fi
  done < <(jq -r ".${kind}Targets[].name" "$contract")
}

select_path() {
  local path=$1 selections name matched
  selections=$(jq -c --arg path "$path" '
    first(.pathRules[] | . as $rule | select($path | test($rule.pattern))) // .fallback
  ' "$contract")
  matched=$(jq -r --arg path "$path" '
    any(.pathRules[]; . as $rule | $path | test($rule.pattern))
  ' "$contract")
  if [[ $matched != true ]]; then
    classification_reason=unknown-path
  fi
  while IFS= read -r name; do
    [[ -n $name ]] || continue
    if [[ $name == '*' ]]; then select_all validation; else validation_names["$name"]=1; fi
  done < <(jq -r '.validation[]?' <<<"$selections")
  while IFS= read -r name; do
    [[ -n $name ]] || continue
    if [[ $name == '*' ]]; then select_all publication; else publication_names["$name"]=1; fi
  done < <(jq -r '.publication[]?' <<<"$selections")
}

classify_range() {
  local base=$1 head=$2 path
  git -C "$repo_root" cat-file -e "$base^{commit}" 2>/dev/null || return 1
  git -C "$repo_root" cat-file -e "$head^{commit}" 2>/dev/null || return 1
  git -C "$repo_root" merge-base --is-ancestor "$base" "$head" || return 1
  while IFS= read -r -d '' path; do
    ((changed_path_count += 1))
    select_path "$path"
  done < <(git -C "$repo_root" diff --no-renames --name-only -z "$base" "$head")
  classification_base=$base
  classification_mode=paths
  classification_reason=classified-paths
}

expand_validation_dependencies() {
  local changed=1 name requirement
  while ((changed)); do
    changed=0
    for name in "${!validation_names[@]}"; do
      while IFS= read -r requirement; do
        [[ -n $requirement ]] || continue
        if [[ -z ${validation_names[$requirement]+set} ]]; then
          validation_names["$requirement"]=1
          changed=1
        fi
      done < <(jq -r --arg name "$name" '
        .validationTargets[] | select(.name == $name) | .requires[]?
      ' "$contract")
    done
  done
}

event_json='{}'
if [[ -n $event_path && -f $event_path ]]; then
  event_json=$(<"$event_path")
fi

case "$event_name" in
  pull_request)
    base_sha=$(jq -er '.pull_request.base.sha' <<<"$event_json")
    if ! classify_range "$base_sha" "$head_sha"; then
      select_all validation
      classification_reason=invalid-pull-request-ancestry
    fi
    ;;
  merge_group)
    base_sha=$(jq -er '.merge_group.base_sha' <<<"$event_json")
    merge_head=$(jq -er '.merge_group.head_sha' <<<"$event_json")
    if [[ $merge_head != "$head_sha" ]] || ! classify_range "$base_sha" "$head_sha"; then
      select_all validation
      classification_reason=invalid-merge-group-ancestry
    fi
    ;;
  push)
    before_sha=$(jq -er '.before' <<<"$event_json")
    declare -A pushed_publication=()
    if classify_range "$before_sha" "$head_sha"; then
      publication_changed_path_count=$changed_path_count
      for name in "${!publication_names[@]}"; do pushed_publication["$name"]=1; done
      validation_names=()
      publication_names=()
      changed_path_count=0
      candidate=
      if [[ -n ${GITHUB_REPOSITORY:-} && -n ${GH_TOKEN:-${GITHUB_TOKEN:-}} ]]; then
        while IFS= read -r sha; do
          [[ -n $sha ]] || continue
          if git -C "$repo_root" merge-base --is-ancestor "$sha" "$head_sha" 2>/dev/null; then
            candidate=$sha
            break
          fi
        done < <("${XO_NIXPKG_GH:-gh}" api --paginate \
          "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/runs?event=merge_group&status=success&per_page=100" \
          --jq '.workflow_runs[].head_sha' 2>/dev/null || true)
      fi
      if [[ -n $candidate ]] && classify_range "$candidate" "$head_sha"; then
        classification_mode=reused-merge-group
        classification_reason=merge-group-ancestor-plus-delta
      else
        validation_names=()
        select_all validation
        classification_mode=full
        classification_reason=no-valid-merge-group-ancestor
      fi
      publication_names=()
      for name in "${!pushed_publication[@]}"; do publication_names["$name"]=1; done
    else
      validation_names=()
      publication_names=()
      select_all validation
      select_all publication
      classification_reason=invalid-push-ancestry
    fi
    ;;
  *)
    select_all validation
    ;;
esac

expand_validation_dependencies

names_json() {
  local kind=$1
  if [[ $kind == validation ]]; then
    printf '%s\n' "${!validation_names[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))'
  else
    printf '%s\n' "${!publication_names[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))'
  fi
}

validation_selected=$(names_json validation)
publication_selected=$(names_json publication)
validation_plan=$(jq -c --argjson selected "$validation_selected" '
  [.validationTargets[] | select(.name as $name | $selected | index($name)) |
    del(.requires)] as $targets |
  if ($targets | length) == 0 then null else
    {schemaVersion:2,name:"xo-nixpkg-validation-selected",targets:$targets}
  end
' "$contract")
publication_plan=$(jq -c --argjson selected "$publication_selected" '
  [.publicationTargets[] | select(.name as $name | $selected | index($name))] as $targets |
  if ($targets | length) == 0 then null else
    {schemaVersion:2,name:"xo-nixpkg-publication-selected",targets:$targets}
  end
' "$contract")

publish_enabled=false
release_enabled=false
if [[ $event_name == $(jq -r '.lifecycle.publish.event' "$contract") &&
      $event_ref == $(jq -r '.lifecycle.publish.ref' "$contract") &&
      $publication_plan != null ]]; then
  publish_enabled=true
fi
if [[ $event_name == $(jq -r '.lifecycle.release.event' "$contract") &&
      $event_ref == $(jq -r '.lifecycle.release.ref' "$contract") ]]; then
  release_enabled=true
fi

workflow=$(jq -cn \
  --arg event "$event_name" \
  --arg ref "$event_ref" \
  --arg headSha "$head_sha" \
  --arg baseSha "$classification_base" \
  --arg mode "$classification_mode" \
  --arg reason "$classification_reason" \
  --argjson changedPathCount "$changed_path_count" \
  --argjson publicationChangedPathCount "$publication_changed_path_count" \
  --argjson validationPlan "$validation_plan" \
  --argjson publicationPlan "$publication_plan" \
  --argjson publishEnabled "$publish_enabled" \
  --argjson releaseEnabled "$release_enabled" '
  {
    schemaVersion:2,
    event:{name:$event,ref:$ref,headSha:$headSha},
    classification:({
      mode:$mode,
      reason:$reason,
      changedPathCount:$changedPathCount,
      publicationChangedPathCount:$publicationChangedPathCount
    } +
      if $baseSha == "" then {} else {baseSha:$baseSha} end),
    jobs:{
      validate:{enabled:($validationPlan != null),plan:$validationPlan},
      publish:{enabled:$publishEnabled,plan:$publicationPlan}
    },
    release:{enabled:$releaseEnabled}
  }
')

if [[ -n $output_file ]]; then
  printf 'workflow=%s\n' "$workflow" >>"$output_file"
else
  printf '%s\n' "$workflow"
fi
