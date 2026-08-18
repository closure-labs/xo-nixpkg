#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${UPDATE_BRANCH:?UPDATE_BRANCH must be set}"
: "${UPDATE_TITLE:?UPDATE_TITLE must be set}"
: "${UPDATE_BODY:?UPDATE_BODY must be set}"

(($# > 0)) || { echo 'usage: open-update-pr PATH...' >&2; exit 2; }
git check-ref-format --branch "$UPDATE_BRANCH" >/dev/null
[[ $UPDATE_BRANCH != main ]] || { echo 'Refusing to update main directly' >&2; exit 2; }
for path in "$@"; do
  [[ $path != /* && $path != *..* ]] || {
    printf 'Unsafe update path: %s\n' "$path" >&2
    exit 2
  }
done

if git diff --quiet -- "$@"; then
  echo 'No update changes to publish'
  exit 0
fi

git config user.name 'nixoa-updater[bot]'
git config user.email 'nixoa-updater[bot]@users.noreply.github.com'
git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
remote_sha=$(git ls-remote --refs origin "refs/heads/$UPDATE_BRANCH" | cut -f1)
git switch -C "$UPDATE_BRANCH"
git add -- "$@"
git diff --cached --quiet && { echo 'No allowlisted update changes to publish'; exit 0; }
git commit -m "$UPDATE_TITLE"
git push --force-with-lease="refs/heads/$UPDATE_BRANCH:$remote_sha" \
  origin "HEAD:refs/heads/$UPDATE_BRANCH"

if gh pr view "$UPDATE_BRANCH" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  gh pr edit "$UPDATE_BRANCH" --repo "$GITHUB_REPOSITORY" \
    --title "$UPDATE_TITLE" --body "$UPDATE_BODY"
else
  gh pr create --repo "$GITHUB_REPOSITORY" --base main --head "$UPDATE_BRANCH" \
    --title "$UPDATE_TITLE" --body "$UPDATE_BODY"
fi
