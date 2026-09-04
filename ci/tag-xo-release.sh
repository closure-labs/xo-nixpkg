#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GATED_SHA:?GATED_SHA must be set}"
: "${BASE_SHA:?BASE_SHA must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

for sha_name in GATED_SHA BASE_SHA; do
  sha=${!sha_name}
  [[ $sha =~ ^[a-f0-9]{40}$ ]] || {
    printf 'Invalid %s: %s\n' "$sha_name" "$sha" >&2
    exit 1
  }
  git cat-file -e "$sha^{commit}" 2>/dev/null || {
    printf '%s does not name a commit: %s\n' "$sha_name" "$sha" >&2
    exit 1
  }
done

[[ $(git rev-parse HEAD) == "$GATED_SHA" ]] || {
  echo 'The checkout does not match the gated commit' >&2
  exit 1
}
git merge-base --is-ancestor "$BASE_SHA" "$GATED_SHA" || {
  echo 'The push base is not an ancestor of the gated commit' >&2
  exit 1
}

temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
before_pin=$temporary/before-pin.json
after_pin=$temporary/after-pin.json
git show "$BASE_SHA:nix/sources/xen-orchestra.json" >"$before_pin"
git show "$GATED_SHA:nix/sources/xen-orchestra.json" >"$after_pin"

validate_latest_pin() {
  local pin=$1
  jq -e '
    .schemaVersion == 2 and
    (.channels.latest.version | type == "string" and
      test("^[0-9]+\\.[0-9]+(\\.[0-9]+)?$")) and
    (.channels.latest.rev | type == "string" and
      test("^[a-f0-9]{40}$"))
  ' "$pin" >/dev/null || {
    printf 'Malformed latest Xen Orchestra pin in %s\n' "$pin" >&2
    exit 1
  }
}

release_tag_for_version() {
  local version=$1
  if [[ $version =~ ^[0-9]+\.[0-9]+$ ]]; then
    printf 'v%s.0\n' "$version"
  else
    printf 'v%s\n' "$version"
  fi
}

validate_latest_pin "$before_pin"
validate_latest_pin "$after_pin"

before_version=$(jq -er '.channels.latest.version' "$before_pin")
before_revision=$(jq -er '.channels.latest.rev' "$before_pin")
after_version=$(jq -er '.channels.latest.version' "$after_pin")
after_revision=$(jq -er '.channels.latest.rev' "$after_pin")
if [[ $before_version == "$after_version" && $before_revision == "$after_revision" ]]; then
  echo 'The latest Xen Orchestra version and revision are unchanged; no package tag is needed'
  exit 0
fi

release_tag=$(release_tag_for_version "$after_version")

existing=$(git rev-list -n 1 "$release_tag" 2>/dev/null || true)
if [[ -n $existing && $existing != "$GATED_SHA" ]]; then
  printf 'Immutable XO package tag %s already points to %s, not gated commit %s\n' \
    "$release_tag" "$existing" "$GATED_SHA" >&2
  exit 1
fi
if [[ $existing == "$GATED_SHA" ]]; then
  printf '%s already points to the gated XO package commit\n' "$release_tag"
  exit 0
fi

git tag "$release_tag" "$GATED_SHA"
git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
git push origin "refs/tags/$release_tag"
