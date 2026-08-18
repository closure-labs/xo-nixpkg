#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
repository="$temporary/repository"
mkdir -p "$repository" "$temporary/bin"

git -C "$repository" init -q
git -C "$repository" config user.name fixture
git -C "$repository" config user.email fixture@example.invalid
printf '0.8.0\n' >"$repository/VERSION"
cat >"$repository/CHANGELOG.md" <<'CHANGELOG'
# Changelog

## Unreleased

- This must not appear in release notes.

## [0.8.0] - 2026-08-18

### Added

- Immutable tagged release fixture.

## [0.7.0] - 2026-07-01

- Older release notes.
CHANGELOG
git -C "$repository" add VERSION CHANGELOG.md
git -C "$repository" commit -qm fixture
git -C "$repository" tag v0.8.0

printf '#!%s\n' "$(command -v bash)" >"$temporary/bin/gh"
cat >>"$temporary/bin/gh" <<'SH'
set -euo pipefail
if [[ $1 == release && $2 == view ]]; then
  [[ ${FIXTURE_RELEASE_EXISTS:-false} == true ]]
  exit
fi
printf '%s\n' "$*" >>"$FIXTURE_GH_LOG"
while (( $# > 0 )); do
  if [[ $1 == --notes-file ]]; then
    cp "$2" "$FIXTURE_RELEASE_NOTES"
    exit 0
  fi
  shift
done
SH
chmod +x "$temporary/bin/gh"

: >"$temporary/gh.log"
PATH="$temporary/bin:$PATH" \
GH_TOKEN=fixture \
GITHUB_REPOSITORY=example/repository \
XO_NIXPKG_SOURCE_ROOT="$repository" \
FIXTURE_GH_LOG="$temporary/gh.log" \
FIXTURE_RELEASE_NOTES="$temporary/notes.md" \
  bash "$root/ci/publish-release.sh"

grep -F 'release create v0.8.0' "$temporary/gh.log" >/dev/null
grep -F 'Immutable tagged release fixture.' "$temporary/notes.md" >/dev/null
if grep -E 'Unreleased|Older release notes' "$temporary/notes.md"; then
  echo 'Release notes escaped the tagged changelog section' >&2
  exit 1
fi

: >"$temporary/gh.log"
PATH="$temporary/bin:$PATH" \
GH_TOKEN=fixture \
GITHUB_REPOSITORY=example/repository \
XO_NIXPKG_SOURCE_ROOT="$repository" \
FIXTURE_RELEASE_EXISTS=true \
FIXTURE_GH_LOG="$temporary/gh.log" \
FIXTURE_RELEASE_NOTES="$temporary/notes.md" \
  bash "$root/ci/publish-release.sh"
[[ ! -s $temporary/gh.log ]]
