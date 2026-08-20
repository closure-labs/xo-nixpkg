#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/classifier-test.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT

jq -e '
  [.publicationTargets[].name] == ["xo-latest", "xo-stable", "xo-rolling"] and
  ([.pathRules[] |
    select(.pattern == "^(nix/libvhdi\\.nix|nix/sources/libvhdi\\.json)$") |
    .publication[]] == ["xo-latest", "xo-stable", "xo-rolling"])
' "$root/ci/classifier.json" >/dev/null

fixture=$temporary/repository
mkdir -p "$fixture"
git -C "$fixture" init -q
git -C "$fixture" config user.name fixture
git -C "$fixture" config user.email fixture@example.invalid
printf 'base\n' >"$fixture/default.nix"
git -C "$fixture" add default.nix
git -C "$fixture" commit -qm base
base=$(git -C "$fixture" rev-parse HEAD)

mkdir -p "$fixture/docs"
printf 'documentation\n' >"$fixture/docs/index.md"
git -C "$fixture" add docs/index.md
git -C "$fixture" commit -qm docs
docs_head=$(git -C "$fixture" rev-parse HEAD)

classify() {
  XO_NIXPKG_SOURCE_ROOT="$fixture" \
  XO_NIXPKG_CLASSIFIER_CONTRACT="$root/ci/classifier.json" \
  GITHUB_EVENT_PATH="$temporary/event.json" \
  GITHUB_EVENT_NAME="$1" \
  GITHUB_REF="$2" \
  GITHUB_SHA="$3" \
  GITHUB_REPOSITORY=fixture/repository \
  GH_TOKEN=fixture \
  XO_NIXPKG_GH="$temporary/gh" \
    bash "$root/ci/classify.sh"
}

jq -n --arg base "$base" '{pull_request:{base:{sha:$base}}}' >"$temporary/event.json"
docs_plan=$(classify pull_request refs/pull/1/merge "$docs_head")
jq -e '
  .schemaVersion == 2 and
  .classification.mode == "paths" and
  .jobs.validate.enabled == false and
  .jobs.publish.enabled == false and
  .release.enabled == false
' <<<"$docs_plan" >/dev/null

printf 'package change\n' >>"$fixture/default.nix"
git -C "$fixture" add default.nix
git -C "$fixture" commit -qm package
package_head=$(git -C "$fixture" rev-parse HEAD)
jq -n --arg base "$docs_head" '{pull_request:{base:{sha:$base}}}' >"$temporary/event.json"
package_plan=$(classify pull_request refs/pull/2/merge "$package_head")
jq -e '
  [.jobs.validate.plan.targets[].name] ==
    ["xo-latest", "xo-stable", "xo-rolling", "xo-fuse-linkage", "xo-server-service"]
' <<<"$package_plan" >/dev/null

# The generated fixture expands this variable when it runs.
# shellcheck disable=SC2016
printf '#!%s\nprintf "%%s\\n" "$FAKE_MERGE_GROUP_SHA"\n' "$(command -v bash)" >"$temporary/gh"
chmod +x "$temporary/gh"
jq -n --arg before "$docs_head" '{before:$before}' >"$temporary/event.json"
FAKE_MERGE_GROUP_SHA="$package_head" export FAKE_MERGE_GROUP_SHA
push_plan=$(classify push refs/heads/main "$package_head")
jq -e '
  .classification.mode == "reused-merge-group" and
  .jobs.validate.enabled == false and
  .jobs.publish.enabled == true and
  [.jobs.publish.plan.targets[].name] == ["xo-latest", "xo-stable", "xo-rolling"] and
  .release.enabled == true
' <<<"$push_plan" >/dev/null

printf 'more docs\n' >>"$fixture/docs/index.md"
git -C "$fixture" add docs/index.md
git -C "$fixture" commit -qm docs-delta
delta_head=$(git -C "$fixture" rev-parse HEAD)
jq -n --arg before "$docs_head" '{before:$before}' >"$temporary/event.json"
delta_plan=$(classify push refs/heads/main "$delta_head")
jq -e '
  .classification.reason == "merge-group-ancestor-plus-delta" and
  .jobs.validate.enabled == false and
  [.jobs.publish.plan.targets[].name] == ["xo-latest", "xo-stable", "xo-rolling"]
' <<<"$delta_plan" >/dev/null

git -C "$fixture" checkout -q --orphan unrelated
git -C "$fixture" rm -q -rf .
printf 'unrelated\n' >"$fixture/unrelated"
git -C "$fixture" add unrelated
git -C "$fixture" commit -qm unrelated
unrelated=$(git -C "$fixture" rev-parse HEAD)
jq -n --arg base "$unrelated" --arg head "$delta_head" \
  '{merge_group:{base_sha:$base,head_sha:$head}}' >"$temporary/event.json"
invalid_plan=$(classify merge_group refs/heads/gh-readonly-queue/main/pr-1 "$delta_head")
jq -e '
  .classification.reason == "invalid-merge-group-ancestry" and
  (.jobs.validate.plan.targets | length) == 14
' <<<"$invalid_plan" >/dev/null

printf '{}\n' >"$temporary/event.json"
dispatch_plan=$(classify workflow_dispatch refs/heads/main "$delta_head")
jq -e '
  .classification.reason == "event-does-not-classify-paths" and
  (.jobs.validate.plan.targets | length) == 14 and
  .jobs.publish.enabled == false and
  .release.enabled == false
' <<<"$dispatch_plan" >/dev/null

printf 'Classifier fixtures passed\n'
