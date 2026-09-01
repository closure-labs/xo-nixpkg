#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${PR_AUTHOR:?PR_AUTHOR must be set}"
: "${PR_HEAD_REF:?PR_HEAD_REF must be set}"
: "${PR_HEAD_REPOSITORY:?PR_HEAD_REPOSITORY must be set}"
: "${PR_HEAD_SHA:?PR_HEAD_SHA must be set}"

[[ $PR_AUTHOR == 'dependabot[bot]' ]] || {
  printf 'Refusing to repair hashes for untrusted PR author %s\n' "$PR_AUTHOR" >&2
  exit 2
}
[[ $PR_HEAD_REPOSITORY == "$GITHUB_REPOSITORY" ]] || {
  printf 'Refusing to push to foreign PR repository %s\n' "$PR_HEAD_REPOSITORY" >&2
  exit 2
}
[[ $PR_HEAD_REF == dependabot/* ]] || {
  printf 'Refusing non-Dependabot branch %s\n' "$PR_HEAD_REF" >&2
  exit 2
}
[[ $PR_HEAD_SHA =~ ^[a-f0-9]{40}$ ]] || {
  printf 'Invalid pull-request head SHA: %s\n' "$PR_HEAD_SHA" >&2
  exit 2
}
git check-ref-format --branch "$PR_HEAD_REF" >/dev/null

repo_root=${XO_NIXPKG_SOURCE_ROOT:-$PWD}
cd "$repo_root"
[[ -z $(git status --porcelain) ]] || {
  echo 'Trusted hash-fixer checkout must start clean' >&2
  exit 1
}

git fetch --no-tags --depth=1 origin "refs/heads/$PR_HEAD_REF"
fetched_sha=$(git rev-parse FETCH_HEAD)
[[ $fetched_sha == "$PR_HEAD_SHA" ]] || {
  printf 'Fetched PR head %s, expected %s\n' "$fetched_sha" "$PR_HEAD_SHA" >&2
  exit 1
}
git checkout --detach "$PR_HEAD_SHA"

push_token=$GH_TOKEN
unset GH_TOKEN GITHUB_TOKEN
determinate-nixd fix hashes --auto-apply

if git diff --quiet; then
  echo 'Determinate Nix found no tracked hash repairs to commit'
  exit 0
fi

git add --update --ignore-removal .
if git diff --cached --quiet; then
  echo 'Determinate Nix changed no allowlisted tracked files'
  exit 0
fi

git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git commit -m '[dependabot skip] Automatically fix Nix hashes'

export GH_TOKEN=$push_token
unset push_token
gh auth setup-git
git push --force-with-lease="refs/heads/$PR_HEAD_REF:$PR_HEAD_SHA" \
  origin "HEAD:refs/heads/$PR_HEAD_REF"
