#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${UPDATE_BRANCH:?UPDATE_BRANCH must be set}"
: "${UPDATE_TITLE:?UPDATE_TITLE must be set}"
: "${UPDATE_BODY:?UPDATE_BODY must be set}"
update_draft=${UPDATE_DRAFT:-false}
retry_attempts=${XO_NIXPKG_RETRY_ATTEMPTS:-3}
retry_delay_seconds=${XO_NIXPKG_RETRY_DELAY_SECONDS:-2}
[[ $update_draft == true || $update_draft == false ]] || {
  echo 'UPDATE_DRAFT must be true or false' >&2
  exit 2
}
[[ $retry_attempts =~ ^[1-9][0-9]*$ && $retry_delay_seconds =~ ^[0-9]+$ ]] || {
  echo 'Retry attempts must be positive and retry delay must be non-negative' >&2
  exit 2
}

is_transient_failure() {
  local output=$1
  [[ $output =~ HTTP[^0-9]*(408|429|5[0-9][0-9]) ]] ||
    [[ $output =~ (Bad[[:space:]]Gateway|Service[[:space:]]Unavailable|Internal[[:space:]]Server[[:space:]]Error) ]] ||
    [[ $output =~ (connection[[:space:]](reset|closed|timed[[:space:]]out)|Connection[[:space:]]refused) ]] ||
    [[ $output =~ (Could[[:space:]]not[[:space:]]resolve|Failed[[:space:]]to[[:space:]]connect|Network[[:space:]]is[[:space:]]unreachable) ]] ||
    [[ $output =~ (TLS|unexpected[[:space:]]EOF|remote[[:space:]]end[[:space:]]hung[[:space:]]up) ]]
}

retry_transient() {
  local operation=$1
  shift
  local attempt output status
  for ((attempt = 1; attempt <= retry_attempts; attempt += 1)); do
    if output=$("$@" 2>&1); then
      [[ -z $output ]] || printf '%s\n' "$output"
      return 0
    else
      status=$?
    fi
    if ((attempt == retry_attempts)) || ! is_transient_failure "$output"; then
      printf '%s\n' "$output" >&2
      printf '%s failed after %s attempt(s)\n' "$operation" "$attempt" >&2
      return "$status"
    fi
    printf '%s hit a transient failure on attempt %s/%s; retrying\n' \
      "$operation" "$attempt" "$retry_attempts" >&2
    sleep "$retry_delay_seconds"
  done
}

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

git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
remote_sha=$(git ls-remote --refs origin "refs/heads/$UPDATE_BRANCH" | cut -f1)
candidate_published=false
if [[ -n $remote_sha ]] && git diff --quiet "$remote_sha" -- "$@"; then
  echo 'The candidate is already published on the update branch'
  candidate_published=true
fi
if [[ $candidate_published == false ]]; then
  git switch -C "$UPDATE_BRANCH"
  git add -- "$@"
  git diff --cached --quiet && { echo 'No allowlisted update changes to publish'; exit 0; }
  git commit -m "$UPDATE_TITLE"
  retry_transient "Push update branch $UPDATE_BRANCH" \
    git push --force-with-lease="refs/heads/$UPDATE_BRANCH:$remote_sha" \
      origin "HEAD:refs/heads/$UPDATE_BRANCH"
fi

open_pr_json=$(gh pr list --repo "$GITHUB_REPOSITORY" --state open --head "$UPDATE_BRANCH" \
  --json isDraft,number --jq '.[0] // {}')
open_pr=$(jq -r '.number // empty' <<<"$open_pr_json")
if [[ -n $open_pr ]]; then
  retry_transient "Edit update PR $open_pr" \
    gh pr edit "$open_pr" --repo "$GITHUB_REPOSITORY" \
      --title "$UPDATE_TITLE" --body "$UPDATE_BODY"
  if [[ $update_draft == true && $(jq -r '.isDraft' <<<"$open_pr_json") == false ]]; then
    retry_transient "Convert update PR $open_pr to draft" \
      gh pr ready --undo "$open_pr" --repo "$GITHUB_REPOSITORY"
  fi
else
  draft_args=()
  [[ $update_draft == false ]] || draft_args+=(--draft)
  retry_transient "Create update PR for $UPDATE_BRANCH" \
    gh pr create --repo "$GITHUB_REPOSITORY" --base main --head "$UPDATE_BRANCH" \
      --title "$UPDATE_TITLE" --body "$UPDATE_BODY" "${draft_args[@]}"
fi
