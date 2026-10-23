#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
mode=${1:?Usage: prewarm-candidate.sh release CHANNELS [OUTPUT] | runtime [OUTPUT]}
shift
case $mode in
  release)
    channels=${1:?Official release prewarm requires changed channels}
    shift
    [[ $channels =~ ^(latest|stable)(,(latest|stable))?$ && $channels != latest,latest && $channels != stable,stable ]] || exit 2
    ;;
  runtime) channels= ;;
  *) exit 2 ;;
esac
[[ $# -le 1 ]] || exit 2
output_file=${1:-}
repo_root=${XO_NIXPKG_SOURCE_ROOT:-$PWD}
# Candidate realization uses protected default-branch-owned code.
# The updater may change only its declared pins, never candidate scripts.
if [[ ${GITHUB_ACTIONS:-false} == true ]]; then
  : "${DEFAULT_BRANCH:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}"
  [[ ${GITHUB_REF:-} == "refs/heads/$DEFAULT_BRANCH" ]]
  [[ ${GITHUB_EVENT_NAME:-} == schedule || ${GITHUB_EVENT_NAME:-} == workflow_dispatch ]]
  [[ $(git -C "$repo_root" rev-parse HEAD) == "$GITHUB_SHA" ]]
  gh api "repos/$GITHUB_REPOSITORY/branches/$DEFAULT_BRANCH" |
    jq -e --arg sha "$GITHUB_SHA" '.protected == true and .commit.sha == $sha' >/dev/null
  changed_paths=$(git -C "$repo_root" diff --name-only HEAD)
  while IFS= read -r changed; do
    [[ -n $changed ]] || continue
    case "$mode:$changed" in
      runtime:flake.lock | runtime:devenv.lock | release:flake.lock | release:flake.nix | release:nix/sources/xen-orchestra.json) ;;
      *) echo 'Prewarm checkout contains changes outside trusted updater pins.' >&2; exit 1 ;;
    esac
  done <<<"$changed_paths"
fi
evidence_dir=${XO_NIXPKG_CI_EVIDENCE:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/xo-nixpkg-ci-evidence}
mkdir -p "$evidence_dir"
plan=$(mktemp)
trap 'rm -f -- "$plan"' EXIT
if [[ $mode == runtime ]]; then
  jq -n '{schemaVersion:2,name:"xo-trusted-runtime-prewarm",targets:[{name:"runtime-node",attribute:"packages.x86_64-linux.runtime-node"}]}' >"$plan"
else
  jq -n --arg channels "$channels" '
    {schemaVersion:2,name:"xo-trusted-release-prewarm",targets:[$channels | split(",")[] | . as $channel |
      {name:("xo-"+$channel),attribute:("packages.x86_64-linux."+$channel)},
      {name:("supply-protector-"+$channel),attribute:("packages.x86_64-linux.supply-protector-"+$channel)}]}
  ' >"$plan"
fi
flake_ref="git+file://$repo_root"
manifest=$evidence_dir/prewarm-$mode.json
rm -f -- "$manifest" "$evidence_dir/prewarm-$mode-timings.json"
flake-plan-runner --flake "$flake_ref" --plan-file "$plan" \
  --manifest "$manifest" --timings "$evidence_dir/prewarm-$mode-timings.json"
# Validate exact planned outputs before retaining local realization evidence.
while IFS=$'\t' read -r attribute output; do
  expected=$(nix eval --accept-flake-config --no-write-lock-file --raw "$flake_ref#$attribute.outPath")
  [[ $output == "$expected" ]] || { echo 'Prewarm output differs from planned package.' >&2; exit 1; }
done < <(jq -er '.results[] | select(.status == "success" and (.outputs|length)==1) | [.attribute,.outputs[0]] | @tsv' "$manifest")
jq -e 'all(.results[]; .status == "success" and (.outputs|length)==1)' "$manifest" >/dev/null
mapfile -t paths < <(jq -er '[.results[].outputs[]] | unique[]' "$manifest")
[[ ${#paths[@]} -gt 0 ]]
closure_path_count=$(nix path-info --recursive "${paths[@]}" | sort -u | wc -l)
((closure_path_count > 0))
if [[ -n $output_file ]]; then
  printf 'closure_path_count=%s\n' "$closure_path_count" >>"$output_file"
fi
