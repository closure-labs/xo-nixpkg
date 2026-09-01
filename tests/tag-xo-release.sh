#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT

real_git=$(command -v git)
git() {
  if [[ ${1-} == remote && ${2-} == set-url ]] || [[ ${1-} == push ]]; then
    return 0
  fi
  command "$REAL_GIT" "$@"
}
export REAL_GIT=$real_git
export -f git
export GH_TOKEN=fixture
export GITHUB_REPOSITORY=example/repository

repository=$fixture/repository
mkdir -p "$repository/nix/sources"
cd "$repository"
git init -q
git config user.name Fixture
git config user.email fixture@example.invalid

write_pin() {
  local latest_version=$1 latest_revision=$2 stable_revision=$3 rolling_revision=$4
  jq -n \
    --arg latest_version "$latest_version" \
    --arg latest_revision "$latest_revision" \
    --arg stable_revision "$stable_revision" \
    --arg rolling_revision "$rolling_revision" '
    {
      schemaVersion: 2,
      channels: {
        latest: {version: $latest_version, rev: $latest_revision},
        stable: {version: "6.7", rev: $stable_revision},
        rolling: {version: "unstable-2026-09-01", rev: $rolling_revision}
      }
    }
  ' >nix/sources/xen-orchestra.json
}

commit_pin() {
  local message=$1
  git add nix/sources/xen-orchestra.json
  git commit -qm "$message"
  git rev-parse HEAD
}

run_tagger() {
  BASE_SHA=$1 GATED_SHA=$2 bash "$root/ci/tag-xo-release.sh"
}

expect_failure() {
  if "$@" >"$fixture/expected-failure.log" 2>&1; then
    echo 'XO package tagger unexpectedly accepted an invalid fixture' >&2
    exit 1
  fi
}

rev_671=1111111111111111111111111111111111111111
rev_68=2222222222222222222222222222222222222222
rev_681=3333333333333333333333333333333333333333
stable_a=4444444444444444444444444444444444444444
stable_b=5555555555555555555555555555555555555555
rolling_a=6666666666666666666666666666666666666666
rolling_b=7777777777777777777777777777777777777777

write_pin 6.7.1 "$rev_671" "$stable_a" "$rolling_a"
base=$(commit_pin base)

write_pin 6.7.1 "$rev_671" "$stable_b" "$rolling_a"
stable_only=$(commit_pin stable-only)
run_tagger "$base" "$stable_only" >/dev/null
[[ -z $(git tag --list 'v*') ]]

write_pin 6.7.1 "$rev_671" "$stable_b" "$rolling_b"
rolling_only=$(commit_pin rolling-only)
run_tagger "$stable_only" "$rolling_only" >/dev/null
[[ -z $(git tag --list 'v*') ]]

printf 'documentation\n' >README.md
git add README.md
git commit -qm unrelated
unrelated=$(git rev-parse HEAD)
run_tagger "$rolling_only" "$unrelated" >/dev/null
[[ -z $(git tag --list 'v*') ]]

jq '.channels.latest.yarnHash = "fixture"' \
  nix/sources/xen-orchestra.json >"$fixture/pin.json"
mv "$fixture/pin.json" nix/sources/xen-orchestra.json
unchanged_latest=$(commit_pin unchanged-latest)
run_tagger "$unrelated" "$unchanged_latest" >/dev/null
[[ -z $(git tag --list 'v*') ]]

write_pin 6.8 "$rev_68" "$stable_b" "$rolling_b"
release_68=$(commit_pin release-6.8)
run_tagger "$unchanged_latest" "$release_68"
[[ $(git rev-list -n 1 v6.8.0) == "$release_68" ]]
[[ $(git cat-file -t v6.8.0) == commit ]]

# Rerunning the same gated push is idempotent.
tag_before=$(git show-ref --hash refs/tags/v6.8.0)
run_tagger "$unchanged_latest" "$release_68" >/dev/null
[[ $(git show-ref --hash refs/tags/v6.8.0) == "$tag_before" ]]

write_pin 6.8.1 "$rev_681" "$stable_b" "$rolling_b"
release_681=$(commit_pin release-6.8.1)
run_tagger "$release_68" "$release_681"
[[ $(git rev-list -n 1 v6.8.1) == "$release_681" ]]

# An existing immutable XO package tag is reported and never moved.
git tag v6.9.0 "$base"
write_pin 6.9 8888888888888888888888888888888888888888 "$stable_b" "$rolling_b"
release_69=$(commit_pin release-6.9)
run_tagger "$release_681" "$release_69" >/dev/null
[[ $(git rev-list -n 1 v6.9.0) == "$base" ]]

expect_failure run_tagger invalid "$release_69"
expect_failure run_tagger "$release_681" invalid
expect_failure run_tagger "$base" "$release_681"

write_pin 6.9.0.1 9999999999999999999999999999999999999999 "$stable_b" "$rolling_b"
malformed=$(commit_pin malformed-version)
expect_failure run_tagger "$release_69" "$malformed"

git checkout -q --orphan nonancestor
git rm -q -rf .
printf 'unrelated history\n' >state
git add state
git commit -qm nonancestor
nonancestor=$(git rev-parse HEAD)
git checkout -q "$release_69"
expect_failure run_tagger "$nonancestor" "$release_69"

printf 'XO package tag fixtures passed\n'
