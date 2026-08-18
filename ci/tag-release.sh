#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${APP_TOKEN:?APP_TOKEN must be set}"
: "${GATED_SHA:?GATED_SHA must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

[[ $(git rev-parse HEAD) == "$GATED_SHA" ]] || {
  echo 'The checkout does not match the gated commit' >&2
  exit 1
}

version=$(nix eval --accept-flake-config --raw .#xen-orchestra-ce.version)
release_tag="v$version"
if ! [[ $release_tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid release tag: $release_tag" >&2
  exit 1
fi

existing=$(git rev-list -n 1 "$release_tag" 2>/dev/null || true)
git tag -f latest "$GATED_SHA"

refs=(refs/tags/latest)
if [[ -z $existing ]]; then
  git tag "$release_tag" "$GATED_SHA"
  refs+=("refs/tags/$release_tag")

  previous_tag=$(git tag --list 'v*.*.*' --sort=-version:refname | grep -Fxv "$release_tag" | head -n 1 || true)
  if [[ -n $previous_tag ]]; then
    git tag -f stable "$previous_tag"
    refs+=(refs/tags/stable)
  fi
elif [[ $existing == "$GATED_SHA" ]]; then
  echo "$release_tag already points to the gated commit"
  refs+=("refs/tags/$release_tag")
else
  echo "$release_tag remains on $existing; advancing latest only"
fi

git remote set-url origin "https://x-access-token:${APP_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
git push --force origin "${refs[@]}"
