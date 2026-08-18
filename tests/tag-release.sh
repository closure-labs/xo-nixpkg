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
export APP_TOKEN=fixture
export GITHUB_REPOSITORY=example/repository

cd "$fixture/repository"
git init -q
git config user.name Fixture
git config user.email fixture@example.invalid

printf 'first\n' >state
git add state
git commit -qm first
first=$(git rev-parse HEAD)
git tag v6.7.1
git tag stable

printf 'release\n' >state
printf '0.8.0\n' >VERSION
git add VERSION state
git commit -qm release
release=$(git rev-parse HEAD)
GATED_SHA=$release bash "$root/ci/tag-release.sh"

[[ $(git rev-list -n 1 v0.8.0) == "$release" ]]
[[ $(git rev-list -n 1 latest) == "$release" ]]
[[ $(git rev-list -n 1 stable) == "$release" ]]
[[ $(git rev-list -n 1 v6.7.1) == "$first" ]]

printf 'packaging\n' >state
git commit -qam packaging
packaging=$(git rev-parse HEAD)
GATED_SHA=$packaging bash "$root/ci/tag-release.sh"

[[ $(git rev-list -n 1 v0.8.0) == "$release" ]]
[[ $(git rev-list -n 1 latest) == "$packaging" ]]
[[ $(git rev-list -n 1 stable) == "$release" ]]

printf '0.9.0\n' >VERSION
git commit -qam next-release
next_release=$(git rev-parse HEAD)
GATED_SHA=$next_release bash "$root/ci/tag-release.sh"

[[ $(git rev-list -n 1 v0.9.0) == "$next_release" ]]
[[ $(git rev-list -n 1 latest) == "$next_release" ]]
[[ $(git rev-list -n 1 stable) == "$release" ]]

printf 'Tag release fixtures passed\n'
