#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${UPDATE_BRANCH:?UPDATE_BRANCH must be set}"
: "${UPDATE_TITLE:?UPDATE_TITLE must be set}"
: "${UPDATE_BODY:?UPDATE_BODY must be set}"
update_draft=${UPDATE_DRAFT:-false}
update_reviewer=${UPDATE_REVIEWER:-}
retry_attempts=${XO_NIXPKG_RETRY_ATTEMPTS:-3}
retry_delay_seconds=${XO_NIXPKG_RETRY_DELAY_SECONDS:-2}
[[ $update_draft == true || $update_draft == false ]] || {
  echo 'UPDATE_DRAFT must be true or false' >&2
  exit 2
}
[[ -z $update_reviewer || $update_reviewer =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ ]] || {
  echo 'UPDATE_REVIEWER must be a GitHub username' >&2
  exit 2
}
[[ $retry_attempts =~ ^[1-9][0-9]*$ && $retry_attempts -le 10 &&
   $retry_delay_seconds =~ ^[0-9]+$ && $retry_delay_seconds -le 60 ]] || {
  echo 'Retry attempts must be 1-10 and retry delay must be 0-60 seconds' >&2
  exit 2
}

is_transient_failure() {
  local output=$1
  [[ $output =~ HTTP[^0-9]*(408|429|5[0-9][0-9]) ]] ||
    [[ $output =~ (Bad[[:space:]]Gateway|Service[[:space:]]Unavailable|Internal[[:space:]]Server[[:space:]]Error) ]] ||
    [[ $output =~ (connection[[:space:]](reset|closed|timed[[:space:]]out)|Connection[[:space:]]refused) ]] ||
    [[ $output =~ (Could[[:space:]]not[[:space:]]resolve|Failed[[:space:]]to[[:space:]]connect|Network[[:space:]]is[[:space:]]unreachable) ]] ||
    [[ $output =~ (TLS|unexpected[[:space:]]EOF|remote[[:space:]]end[[:space:]]hung[[:space:]]up) ]] ||
    [[ $output =~ fatal[[:space:]]error[[:space:]]in[[:space:]]commit_refs ]]
}

retry_transient() {
  local operation=$1
  shift
  local attempt output status exponent delay jitter
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
    exponent=$((attempt - 1))
    ((exponent <= 6)) || exponent=6
    delay=$((retry_delay_seconds * (1 << exponent)))
    ((delay <= 60)) || delay=60
    jitter=0
    ((retry_delay_seconds == 0)) || jitter=$((RANDOM % (retry_delay_seconds + 1)))
    sleep "$((delay + jitter))"
  done
}

is_merge_queue_lock_failure() {
  local output=$1
  [[ $output == *'added to a merge queue'* && $output == *'cannot be updated'* ]]
}

dequeue_update_pr_if_needed() {
  local pr_json pr_id pr_number queue_entry queue_query dequeue_mutation
  # shellcheck disable=SC2016
  queue_query='query($pr: ID!) { node(id: $pr) { ... on PullRequest { mergeQueueEntry { id } } } }'
  # shellcheck disable=SC2016
  dequeue_mutation='mutation($pr: ID!) { dequeuePullRequest(input: {id: $pr}) { clientMutationId } }'
  pr_json=$(retry_transient "Find queued update PR for $UPDATE_BRANCH" \
    gh pr list --repo "$GITHUB_REPOSITORY" --state open --head "$UPDATE_BRANCH" \
      --json id,number --jq '.[0] // {}')
  pr_id=$(jq -r '.id // empty' <<<"$pr_json")
  pr_number=$(jq -r '.number // empty' <<<"$pr_json")
  [[ -n $pr_id && -n $pr_number ]] || {
    echo "GitHub reported that $UPDATE_BRANCH is queued, but no matching open PR was found" >&2
    return 1
  }

  queue_entry=$(retry_transient "Read merge-queue state for update PR $pr_number" \
    gh api graphql -F pr="$pr_id" \
      -f query="$queue_query" \
      --jq '.data.node.mergeQueueEntry.id // empty')
  if [[ -z $queue_entry ]]; then
    echo "Update PR $pr_number is no longer queued; retrying the branch update"
    return 0
  fi

  retry_transient "Dequeue update PR $pr_number" \
    gh api graphql -F pr="$pr_id" \
      -f query="$dequeue_mutation"
  echo "Dequeued update PR $pr_number so the newer exact candidate can replace it"
}

push_update_branch() {
  local attempt output status exponent delay jitter
  for ((attempt = 1; attempt <= retry_attempts; attempt += 1)); do
    if output=$(git push --force-with-lease="refs/heads/$UPDATE_BRANCH:$remote_sha" \
      origin "HEAD:refs/heads/$UPDATE_BRANCH" 2>&1); then
      [[ -z $output ]] || printf '%s\n' "$output"
      return 0
    else
      status=$?
    fi

    if ! is_merge_queue_lock_failure "$output"; then
      if ((attempt == retry_attempts)) || ! is_transient_failure "$output"; then
        printf '%s\n' "$output" >&2
        printf 'Push update branch %s failed after %s attempt(s)\n' \
          "$UPDATE_BRANCH" "$attempt" >&2
        return "$status"
      fi
      printf 'Push update branch %s hit a transient failure on attempt %s/%s; retrying\n' \
        "$UPDATE_BRANCH" "$attempt" "$retry_attempts" >&2
    else
      printf '%s\n' "$output" >&2
      if ((attempt == retry_attempts)); then
        printf 'Push update branch %s remained merge-queue locked after %s attempt(s)\n' \
          "$UPDATE_BRANCH" "$attempt" >&2
        return "$status"
      fi
      dequeue_update_pr_if_needed
    fi

    exponent=$((attempt - 1))
    ((exponent <= 6)) || exponent=6
    delay=$((retry_delay_seconds * (1 << exponent)))
    ((delay <= 60)) || delay=60
    jitter=0
    ((retry_delay_seconds == 0)) || jitter=$((RANDOM % (retry_delay_seconds + 1)))
    sleep "$((delay + jitter))"
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
remote_refs=$(retry_transient "Read update branch $UPDATE_BRANCH" \
  git ls-remote --refs origin "refs/heads/$UPDATE_BRANCH")
remote_sha=$(cut -f1 <<<"$remote_refs")
candidate_published=false
if [[ -n $remote_sha ]]; then
  retry_transient "Fetch existing update candidate $UPDATE_BRANCH" \
    git fetch --no-tags --depth=1 origin "$remote_sha"
  if git diff --quiet "$remote_sha" -- .; then
    echo 'The exact candidate tree is already published on the update branch'
    candidate_published=true
  fi
fi
if [[ $candidate_published == false ]]; then
  git switch -C "$UPDATE_BRANCH"
  git add -- "$@"
  git diff --cached --quiet && { echo 'No allowlisted update changes to publish'; exit 0; }
  git commit -m "$UPDATE_TITLE"
  push_update_branch
fi

open_pr_json=$(retry_transient "Find update PR for $UPDATE_BRANCH" \
  gh pr list --repo "$GITHUB_REPOSITORY" --state open --head "$UPDATE_BRANCH" \
    --json isDraft,number --jq '.[0] // {}')
open_pr=$(jq -r '.number // empty' <<<"$open_pr_json")
if [[ -n $open_pr ]]; then
  edit_args=(--title "$UPDATE_TITLE" --body "$UPDATE_BODY")
  [[ -z $update_reviewer ]] || edit_args+=(--add-reviewer "$update_reviewer")
  retry_transient "Edit update PR $open_pr" \
    gh pr edit "$open_pr" --repo "$GITHUB_REPOSITORY" \
      "${edit_args[@]}"
  if [[ $update_draft == true && $(jq -r '.isDraft' <<<"$open_pr_json") == false ]]; then
    retry_transient "Convert update PR $open_pr to draft" \
      gh pr ready --undo "$open_pr" --repo "$GITHUB_REPOSITORY"
  fi
else
  draft_args=()
  reviewer_args=()
  [[ $update_draft == false ]] || draft_args+=(--draft)
  [[ -z $update_reviewer ]] || reviewer_args+=(--reviewer "$update_reviewer")
  retry_transient "Create update PR for $UPDATE_BRANCH" \
    gh pr create --repo "$GITHUB_REPOSITORY" --base main --head "$UPDATE_BRANCH" \
      --title "$UPDATE_TITLE" --body "$UPDATE_BODY" "${draft_args[@]}" "${reviewer_args[@]}"
fi
