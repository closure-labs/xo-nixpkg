#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${APP_TOKEN:?APP_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

"${XO_NIXPKG_SOURCE_ROOT:-$PWD}/ci/update-xo.sh" --upstream

git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
if ! git diff --quiet -- default.nix nix/platform-tools.nix; then
  git add default.nix nix/platform-tools.nix
  rev=$(nix eval --accept-flake-config --raw .#xen-orchestra-ce.src.rev)
  git commit -m "xen-orchestra-ce: track upstream ${rev:0:12}"
fi

git tag -f latest-upstream HEAD
git remote set-url origin "https://x-access-token:${APP_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
git push --force origin refs/tags/latest-upstream
