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
    --json author,baseRefName,headRefName,headRefOid,headRepository,mergeStateStatus,state,title,url
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
if [[ $(jq -er .mergeStateStatus <<<"$pr") == BEHIND ]]; then
  gh pr update-branch "$PR_NUMBER" --repo "$GITHUB_REPOSITORY"
  pr=$(read_pr)
  validate_pr "$pr"
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
  gh api --method POST \
    "repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/approve" >/dev/null
fi
gh run watch "$run_id" --repo "$GITHUB_REPOSITORY" --exit-status

pr=$(read_pr)
validate_pr "$pr"
gh pr merge \
  --repo "$GITHUB_REPOSITORY" \
  --auto \
  --merge \
  --match-head-commit "$head_sha" \
  "$pr_url"
