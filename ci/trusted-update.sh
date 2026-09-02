#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${PR_NUMBER:?PR_NUMBER must be set}"
: "${EXPECTED_BRANCH:?EXPECTED_BRANCH must be set}"
: "${EXPECTED_TITLE:?EXPECTED_TITLE must be set}"
: "${EXPECTED_AUTHOR:?EXPECTED_AUTHOR must be set}"
: "${EXPECTED_HEAD_SHA:?EXPECTED_HEAD_SHA must be set}"
: "${DEFAULT_BRANCH:?DEFAULT_BRANCH must be set}"

ci_workflow=${CI_WORKFLOW:-ci.yml}

read_pr() {
  gh pr view "$PR_NUMBER" \
    --repo "$GITHUB_REPOSITORY" \
    --json author,baseRefName,headRefName,headRefOid,headRepository,mergeStateStatus,reviewDecision,state,title,url
}

validate_pr() {
  local candidate=$1
  local author
  author=$(jq -er .author.login <<<"$candidate")
  author=${author#app/}
  author=${author%\[bot\]}
  [[ $(jq -er .state <<<"$candidate") == OPEN ]]
  [[ $(jq -er .title <<<"$candidate") == "$EXPECTED_TITLE" ]]
  [[ $author == "$EXPECTED_AUTHOR" ]]
  [[ $(jq -er .baseRefName <<<"$candidate") == "$DEFAULT_BRANCH" ]]
  [[ $(jq -er .headRepository.nameWithOwner <<<"$candidate") == "$GITHUB_REPOSITORY" ]]
  [[ $(jq -er .headRefName <<<"$candidate") == "$EXPECTED_BRANCH" ]]
  [[ $(jq -er .headRefOid <<<"$candidate") == "$EXPECTED_HEAD_SHA" ]]
}

pr=$(read_pr)
validate_pr "$pr"
if [[ $(jq -r '.reviewDecision // ""' <<<"$pr") != APPROVED ]]; then
  printf 'Trusted update PR %s is waiting for human approval.\n' "$PR_NUMBER"
  exit 0
fi
if [[ $(jq -er .mergeStateStatus <<<"$pr") == BEHIND ]]; then
  gh pr update-branch "$PR_NUMBER" --repo "$GITHUB_REPOSITORY"
  pr=$(read_pr)
  validate_pr "$pr"
  [[ $(jq -r '.reviewDecision // ""' <<<"$pr") == APPROVED ]] || {
    printf 'Trusted update PR %s requires approval again after its branch update.\n' "$PR_NUMBER"
    exit 0
  }
fi

branch=$(jq -er .headRefName <<<"$pr")
head_sha=$(jq -er .headRefOid <<<"$pr")
pr_url=$(jq -er .url <<<"$pr")
run_id=
run_conclusion=
for _ in {1..12}; do
  run_json=$(gh run list \
    --repo "$GITHUB_REPOSITORY" \
    --workflow "$ci_workflow" \
    --event pull_request \
    --branch "$branch" \
    --commit "$head_sha" \
    --limit 1 \
    --json conclusion,databaseId)
  run_id=$(jq -r '.[0].databaseId // empty' <<<"$run_json")
  run_conclusion=$(jq -r '.[0].conclusion // empty' <<<"$run_json")
  [[ -z $run_id ]] || break
  sleep 5
done

[[ -n $run_id ]] || {
  printf 'Could not locate approval-gated pull-request CI for trusted update %s at %s.\n' \
    "$PR_NUMBER" "$head_sha" >&2
  exit 1
}

if [[ $run_conclusion == action_required ]]; then
  if ! approval_error=$(gh api --method POST \
    "repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/approve" 2>&1); then
    printf 'Could not approve action-required CI run %s for PR %s at %s.\n' \
      "$run_id" "$PR_NUMBER" "$head_sha" >&2
    printf '%s\n' \
      'MERGE_QUEUE_TOKEN must be a repository-scoped fine-grained PAT with Actions write permission.' >&2
    printf 'GitHub response: %s\n' "$approval_error" >&2
    exit 1
  fi
fi
gh run watch "$run_id" --repo "$GITHUB_REPOSITORY" --exit-status

pr=$(read_pr)
validate_pr "$pr"
if ! merge_error=$(gh pr merge \
  --repo "$GITHUB_REPOSITORY" \
  --auto \
  --merge \
  --match-head-commit "$head_sha" \
  "$pr_url" 2>&1); then
  printf 'Could not enroll PR %s at validated head %s in the merge queue.\n' \
    "$PR_NUMBER" "$head_sha" >&2
  printf '%s\n' \
    'Verify MERGE_QUEUE_TOKEN has Contents and Pull requests write permissions and that repository auto-merge and merge-queue policy permit this PR.' >&2
  printf 'GitHub response: %s\n' "$merge_error" >&2
  exit 1
fi
[[ -z $merge_error ]] || printf '%s\n' "$merge_error"
