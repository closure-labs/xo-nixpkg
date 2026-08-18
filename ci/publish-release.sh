#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

repo_root=${XO_NIXPKG_SOURCE_ROOT:-$PWD}
version=$(tr -d '\r\n' <"$repo_root/VERSION")
tag="v$version"
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  printf 'Invalid release tag: %s\n' "$tag" >&2
  exit 1
}

git -C "$repo_root" rev-parse --verify "$tag^{commit}" >/dev/null
tagged_version=$(git -C "$repo_root" show "$tag:VERSION" | tr -d '\r\n')
[[ $tagged_version == "$version" ]] || {
  printf '%s contains project version %s, expected %s\n' "$tag" "$tagged_version" "$version" >&2
  exit 1
}

if release_json=$(gh release view "$tag" --repo "$GITHUB_REPOSITORY" \
  --json isDraft,tagName 2>/dev/null); then
  [[ $(jq -er .tagName <<<"$release_json") == "$tag" ]]
  [[ $(jq -er .isDraft <<<"$release_json") == false ]]
  local_tag_commit=$(git -C "$repo_root" rev-parse "$tag^{commit}")
  remote_tag_commit=$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}" \
    --jq .object.sha)
  [[ $remote_tag_commit == "$local_tag_commit" ]] || {
    printf 'Published release %s points to %s, expected %s\n' \
      "$tag" "$remote_tag_commit" "$local_tag_commit" >&2
    exit 1
  }
  printf 'GitHub release %s is already published\n' "$tag"
  exit 0
fi

tagged_changelog=$(mktemp)
release_notes=$(mktemp)
cleanup() {
  rm -f "$tagged_changelog" "$release_notes"
}
trap cleanup EXIT
git -C "$repo_root" show "$tag:CHANGELOG.md" >"$tagged_changelog"

awk -v version="$version" '
  index($0, "## [" version "]") == 1 { found = 1; next }
  found && /^## / { exit }
  found { print }
  END { if (!found) exit 2 }
' "$tagged_changelog" >"$release_notes"

if [[ ! -s $release_notes ]]; then
  printf 'No changelog notes found for %s\n' "$tag" >&2
  exit 1
fi

gh release create "$tag" \
  --repo "$GITHUB_REPOSITORY" \
  --verify-tag \
  --title "$tag" \
  --notes-file "$release_notes" \
  --latest

printf 'Published GitHub release %s\n' "$tag"
