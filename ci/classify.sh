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
  .schemaVersion == 2 and
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

select_xo_channel() {
  local channel=$1
  validation_names["xo-$channel"]=1
  validation_names["supply-protector-$channel"]=1
  publication_names["xo-$channel"]=1
  publication_names["supply-protector-$channel"]=1
  if [[ $channel == latest ]]; then
    validation_names["xo-fuse-linkage"]=1
    validation_names["xo-server-service"]=1
  fi
}

update_expected_flake_input() {
  local input=$1 rev=$2 file=$3 temporary
  temporary=$(mktemp "$(dirname "$file")/.expected-flake.XXXXXX")
  awk -v input="$input" -v rev="$rev" '
    $0 ~ "^    " input " = \\{" { inInput = 1 }
    inInput && $0 ~ /url = "github:vatesfr\/xen-orchestra\/[a-f0-9]+";/ {
      sub(/[a-f0-9]{40}";/, rev "\";")
      inInput = 0
    }
    { print }
  ' "$file" >"$temporary"
  if cmp -s "$file" "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  mv "$temporary" "$file"
}

classify_xo_channel_update() {
  local base=$1 head=$2 path channel old_rev new_rev temporary expected_flake channels_json
  shift 2
  local -a changed_paths=("$@") changed_channels=()

  ((${#changed_paths[@]} >= 2)) || return 1
  for path in "${changed_paths[@]}"; do
    case "$path" in
      flake.nix|flake.lock|nix/sources/xen-orchestra.json) ;;
      *) return 1 ;;
    esac
  done
  printf '%s\n' "${changed_paths[@]}" | grep -Fxq 'nix/sources/xen-orchestra.json' || return 1

  temporary=$(mktemp -d)
  git -C "$repo_root" show "$base:nix/sources/xen-orchestra.json" >"$temporary/before-pin.json" || {
    rm -rf "$temporary"
    return 1
  }
  git -C "$repo_root" show "$head:nix/sources/xen-orchestra.json" >"$temporary/after-pin.json" || {
    rm -rf "$temporary"
    return 1
  }
  jq -e -s '
    (.[0] | del(.channels)) == (.[1] | del(.channels)) and
    (.[0].channels | keys) == ["latest", "rolling", "stable"] and
    (.[1].channels | keys) == ["latest", "rolling", "stable"]
  ' "$temporary/before-pin.json" "$temporary/after-pin.json" >/dev/null || {
    rm -rf "$temporary"
    return 1
  }
  mapfile -t changed_channels < <(jq -r -s '
    .[0] as $before | .[1] as $after |
    ["latest", "stable", "rolling"][] |
    select($before.channels[.] != $after.channels[.])
  ' "$temporary/before-pin.json" "$temporary/after-pin.json")
  ((${#changed_channels[@]} > 0)) || {
    rm -rf "$temporary"
    return 1
  }

  git -C "$repo_root" show "$base:flake.nix" >"$temporary/before-flake.nix" || {
    rm -rf "$temporary"
    return 1
  }
  git -C "$repo_root" show "$head:flake.nix" >"$temporary/after-flake.nix" || {
    rm -rf "$temporary"
    return 1
  }
  expected_flake=$temporary/expected-flake.nix
  cp "$temporary/before-flake.nix" "$expected_flake"
  for channel in "${changed_channels[@]}"; do
    old_rev=$(jq -er --arg channel "$channel" '.channels[$channel].rev' "$temporary/before-pin.json") || {
      rm -rf "$temporary"
      return 1
    }
    new_rev=$(jq -er --arg channel "$channel" '.channels[$channel].rev' "$temporary/after-pin.json") || {
      rm -rf "$temporary"
      return 1
    }
    [[ $old_rev != "$new_rev" ]] || {
      rm -rf "$temporary"
      return 1
    }
    update_expected_flake_input "xo-$channel" "$new_rev" "$expected_flake" || {
      rm -rf "$temporary"
      return 1
    }
  done
  cmp -s "$expected_flake" "$temporary/after-flake.nix" || {
    rm -rf "$temporary"
    return 1
  }

  git -C "$repo_root" show "$base:flake.lock" >"$temporary/before-lock.json" || {
    rm -rf "$temporary"
    return 1
  }
  git -C "$repo_root" show "$head:flake.lock" >"$temporary/after-lock.json" || {
    rm -rf "$temporary"
    return 1
  }
  channels_json=$(printf '%s\n' "${changed_channels[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')
  jq --argjson channels "$channels_json" '
    reduce $channels[] as $channel (.; del(.nodes["xo-" + $channel]))
  ' "$temporary/before-lock.json" >"$temporary/before-lock-normalized.json"
  jq --argjson channels "$channels_json" '
    reduce $channels[] as $channel (.; del(.nodes["xo-" + $channel]))
  ' "$temporary/after-lock.json" >"$temporary/after-lock-normalized.json"
  cmp -s "$temporary/before-lock-normalized.json" "$temporary/after-lock-normalized.json" || {
    rm -rf "$temporary"
    return 1
  }
  for channel in "${changed_channels[@]}"; do
    new_rev=$(jq -er --arg channel "$channel" '.channels[$channel].rev' "$temporary/after-pin.json")
    jq -e --arg channel "xo-$channel" --arg rev "$new_rev" '
      .nodes[$channel].locked.rev == $rev and
      .nodes[$channel].original.rev == $rev
    ' "$temporary/after-lock.json" >/dev/null || {
      rm -rf "$temporary"
      return 1
    }
    select_xo_channel "$channel"
  done
  validation_names["source-update-fixtures"]=1
  classification_reason=semantic-xo-channel-update
  rm -rf "$temporary"
}

classify_range() {
  local base=$1 head=$2 path
  local -a changed_paths=()
  git -C "$repo_root" cat-file -e "$base^{commit}" 2>/dev/null || return 1
  git -C "$repo_root" cat-file -e "$head^{commit}" 2>/dev/null || return 1
  git -C "$repo_root" merge-base --is-ancestor "$base" "$head" || return 1
  classification_reason=classified-paths
  mapfile -d '' -t changed_paths < <(
    git -C "$repo_root" diff --no-renames --name-only -z "$base" "$head"
  )
  changed_path_count=${#changed_paths[@]}
  if ! classify_xo_channel_update "$base" "$head" "${changed_paths[@]}"; then
    for path in "${changed_paths[@]}"; do
      select_path "$path"
    done
  fi
  classification_base=$base
  classification_mode=paths
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
