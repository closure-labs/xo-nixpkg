#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

export XO_NIXPKG_PUBLICATION_PURPOSE=release
xo-nixpkg-publication-gate

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GATED_SHA:?GATED_SHA must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

if [[ -n ${XO_NIXPKG_EVIDENCE:-} ]]; then
  [[ $(jq -er .revision "$XO_NIXPKG_EVIDENCE/product.json") == "$GATED_SHA" ]]
else
  [[ $(git rev-parse HEAD) == "$GATED_SHA" ]]
fi

repo_root=$(git rev-parse --show-toplevel)
version_file=${XO_NIXPKG_VERSION_FILE:-$repo_root/VERSION}
if [[ -n ${XO_NIXPKG_EVIDENCE:-} ]]; then
  version=$(git show "$GATED_SHA:VERSION" | tr -d '\r\n')
else
  version=$(tr -d '\r\n' <"$version_file")
fi
release_tag="v$version"
[[ $release_tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "Invalid release tag: $release_tag" >&2
  exit 1
}

existing=$(git rev-list -n 1 "$release_tag" 2>/dev/null || true)
if [[ -n $existing && $existing != "$GATED_SHA" ]]; then
  printf '%s conflicts with immutable release commit %s\n' "$release_tag" "$existing" >&2
  exit 1
fi
if [[ $existing == "$GATED_SHA" ]]; then
  printf '%s already points to the gated commit\n' "$release_tag"
else
  git tag "$release_tag" "$GATED_SHA"
fi

git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
git push origin "refs/tags/$release_tag"
