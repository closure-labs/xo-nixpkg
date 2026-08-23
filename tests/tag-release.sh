#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

real_git=$(command -v git)
mkdir -p "$fixture/repository"
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

cd "$fixture/repository"
git init -q
git config user.name Fixture
git config user.email fixture@example.invalid
printf 'first\n' >state
git add state
git commit -qm first
first=$(git rev-parse HEAD)
# Existing aliases are deprecated but are not destructively removed.
git tag latest "$first"
git tag stable "$first"

printf 'release\n' >state
printf '0.8.0\n' >VERSION
git add VERSION state
git commit -qm release
release=$(git rev-parse HEAD)
GATED_SHA=$release bash "$root/ci/tag-release.sh"
[[ $(git rev-list -n 1 v0.8.0) == "$release" ]]
[[ $(git rev-list -n 1 latest) == "$first" ]]
[[ $(git rev-list -n 1 stable) == "$first" ]]

# Packaging commits with the same project version do not rewrite its tag.
printf 'packaging\n' >state
git commit -qam packaging
packaging=$(git rev-parse HEAD)
GATED_SHA=$packaging bash "$root/ci/tag-release.sh"
[[ $(git rev-list -n 1 v0.8.0) == "$release" ]]

printf '0.9.0\n' >VERSION
git commit -qam next-release
next_release=$(git rev-parse HEAD)
GATED_SHA=$next_release bash "$root/ci/tag-release.sh"
[[ $(git rev-list -n 1 v0.9.0) == "$next_release" ]]
[[ $(git rev-list -n 1 latest) == "$first" ]]
[[ $(git rev-list -n 1 stable) == "$first" ]]

printf 'Immutable project tag fixtures passed\n'
