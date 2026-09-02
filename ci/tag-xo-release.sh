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

validate_release_pins() {
  local pin=$1
  jq -e '
    .schemaVersion == 2 and
    (.channels.latest.version | type == "string" and
      test("^[0-9]+\\.[0-9]+(\\.[0-9]+)?$")) and
    (.channels.latest.rev | type == "string" and
      test("^[a-f0-9]{40}$")) and
    (.channels.stable.version | type == "string" and
      test("^[0-9]+\\.[0-9]+(\\.[0-9]+)?$")) and
    (.channels.stable.rev | type == "string" and
      test("^[a-f0-9]{40}$"))
  ' "$pin" >/dev/null || {
    printf 'Malformed Xen Orchestra release pin in %s\n' "$pin" >&2
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

validate_release_pins "$before_pin"
validate_release_pins "$after_pin"

before_version=$(jq -er '.channels.latest.version' "$before_pin")
before_revision=$(jq -er '.channels.latest.rev' "$before_pin")
after_version=$(jq -er '.channels.latest.version' "$after_pin")
after_revision=$(jq -er '.channels.latest.rev' "$after_pin")
before_stable_version=$(jq -er '.channels.stable.version' "$before_pin")
before_stable_revision=$(jq -er '.channels.stable.rev' "$before_pin")
after_stable_version=$(jq -er '.channels.stable.version' "$after_pin")
after_stable_revision=$(jq -er '.channels.stable.rev' "$after_pin")

latest_changed=false
stable_changed=false
[[ $before_version == "$after_version" && $before_revision == "$after_revision" ]] || latest_changed=true
[[ $before_stable_version == "$after_stable_version" &&
   $before_stable_revision == "$after_stable_revision" ]] || stable_changed=true
if [[ $latest_changed == false && $stable_changed == false ]]; then
  echo 'The Xen Orchestra release channels are unchanged; no package tags are needed'
  exit 0
fi

release_tag=$(release_tag_for_version "$after_version")
stable_release_tag=$(release_tag_for_version "$after_stable_version")

existing=$(git rev-list -n 1 "$release_tag" 2>/dev/null || true)
if [[ -n $existing && $existing != "$GATED_SHA" ]]; then
  printf '%s remains on its immutable XO package commit %s\n' "$release_tag" "$existing"
elif [[ $existing == "$GATED_SHA" ]]; then
  printf '%s already points to the gated XO package commit\n' "$release_tag"
elif [[ $latest_changed == true ]]; then
  git tag "$release_tag" "$GATED_SHA"
else
  printf 'Latest channel %s has no immutable package tag %s\n' \
    "$after_version" "$release_tag" >&2
  exit 1
fi

latest_target=$(git rev-list -n 1 "$release_tag")
stable_target=$(git rev-list -n 1 "$stable_release_tag" 2>/dev/null || true)
[[ -n $stable_target ]] || {
  printf 'Stable channel %s has no immutable package tag %s\n' \
    "$after_stable_version" "$stable_release_tag" >&2
  exit 1
}

git tag -f latest "$latest_target"
git tag -f stable "$stable_target"
git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
if [[ -z $existing ]]; then
  git push origin "refs/tags/$release_tag"
fi
git push --force origin refs/tags/latest refs/tags/stable
printf 'latest now follows %s; stable now follows %s\n' "$release_tag" "$stable_release_tag"
