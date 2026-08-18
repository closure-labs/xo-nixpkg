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

repo_root=$(git rev-parse --show-toplevel)
version_file=${XO_NIXPKG_VERSION_FILE:-$repo_root/VERSION}
version=$(tr -d '\r\n' <"$version_file")
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

  previous_tag=
  while IFS= read -r candidate; do
    candidate_version=${candidate#v}
    tagged_version=$(git show "$candidate:VERSION" 2>/dev/null | tr -d '\r\n' || true)
    if [[ $tagged_version == "$candidate_version" ]]; then
      previous_tag=$candidate
      break
    fi
  done < <(git tag --list 'v*.*.*' --sort=-version:refname | grep -Fxv "$release_tag")

  if [[ -n $previous_tag ]]; then
    git tag -f stable "$previous_tag"
  else
    git tag -f stable "$release_tag"
  fi
  refs+=(refs/tags/stable)
elif [[ $existing == "$GATED_SHA" ]]; then
  echo "$release_tag already points to the gated commit"
  refs+=("refs/tags/$release_tag")
else
  echo "$release_tag remains on $existing; advancing latest only"
fi

git remote set-url origin "https://x-access-token:${APP_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
git push --force origin "${refs[@]}"
