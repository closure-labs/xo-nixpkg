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
: "${APPROVAL_POLICY:?APPROVAL_POLICY must be set}"

ci_workflow=${CI_WORKFLOW:-ci.yml}
result_file=${TRUSTED_UPDATE_RESULT_FILE:-}

case "$APPROVAL_POLICY" in
  automatic | trusted-maintainer) ;;
  *)
    printf 'Unsupported approval policy: %s\n' "$APPROVAL_POLICY" >&2
    exit 2
    ;;
esac

write_result() {
  local status=$1 message=$2
  printf '%s\n' "$message"
  if [[ -n $result_file ]]; then
    jq -n --arg status "$status" --arg message "$message" \
      '{status:$status,message:$message}' >"$result_file"
  fi
}

complete() {
  write_result "$1" "$2"
  exit 0
}

fail() {
  local message=$1
  write_result policy-error "$message" >&2
  exit 1
}

read_pr() {
  gh pr view "$PR_NUMBER" \
    --repo "$GITHUB_REPOSITORY" \
    --json author,autoMergeRequest,baseRefName,headRefName,headRefOid,headRepository,isDraft,state,title,url
}

validate_pr() {
  local candidate=$1 author
  author=$(jq -er .author.login <<<"$candidate") || fail "PR $PR_NUMBER has no author"
  author=${author#app/}
  author=${author%\[bot\]}
  [[ $(jq -er .state <<<"$candidate") == OPEN ]] || fail "Trusted update PR $PR_NUMBER is not open"
  [[ $(jq -er .isDraft <<<"$candidate") == false ]] || fail "Trusted update PR $PR_NUMBER is a draft"
  [[ $(jq -er .title <<<"$candidate") == "$EXPECTED_TITLE" ]] || fail "Trusted update PR $PR_NUMBER changed title"
  [[ $author == "$EXPECTED_AUTHOR" ]] || fail "Trusted update PR $PR_NUMBER changed author"
  [[ $(jq -er .baseRefName <<<"$candidate") == "$DEFAULT_BRANCH" ]] || fail "Trusted update PR $PR_NUMBER changed base"
  [[ $(jq -er .headRepository.nameWithOwner <<<"$candidate") == "$GITHUB_REPOSITORY" ]] || fail "Trusted update PR $PR_NUMBER changed head repository"
  [[ $(jq -er .headRefName <<<"$candidate") == "$EXPECTED_BRANCH" ]] || fail "Trusted update PR $PR_NUMBER changed branch"
  [[ $(jq -er .headRefOid <<<"$candidate") == "$EXPECTED_HEAD_SHA" ]] || fail "Trusted update PR $PR_NUMBER changed head SHA"
}

has_exact_head_maintainer_approval() {
  local reviews reviewers reviewer permission_error permission
  if ! reviews=$(gh api --paginate \
    "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100" \
    --slurp); then
    return 2
  fi

  if ! reviewers=$(jq -r --arg head "$EXPECTED_HEAD_SHA" '
    add
    | map(select(
        .commit_id == $head and
        (.state == "APPROVED" or .state == "CHANGES_REQUESTED" or .state == "DISMISSED")
      ))
    | group_by(.user.login)
    | map(max_by(.id))
    | .[]
    | select(.state == "APPROVED")
    | .user.login
  ' <<<"$reviews"); then
    return 2
  fi

  while IFS= read -r reviewer; do
    [[ -n $reviewer ]] || continue
    permission_error=$(mktemp)
    if permission=$(gh api \
      "repos/${GITHUB_REPOSITORY}/collaborators/${reviewer}/permission" \
      --jq '.permission // .role_name' 2>"$permission_error"); then
      rm -f "$permission_error"
      case "$permission" in
        admin | maintain | write) return 0 ;;
      esac
    elif [[ $(<"$permission_error") == *"HTTP 404"* ]]; then
      rm -f "$permission_error"
    else
      cat "$permission_error" >&2
      rm -f "$permission_error"
      return 2
    fi
  done <<<"$reviewers"
  return 1
}

if ! pr=$(read_pr); then
  fail "Could not read trusted update PR $PR_NUMBER"
fi
validate_pr "$pr"

branch=$(jq -er .headRefName <<<"$pr")
head_sha=$(jq -er .headRefOid <<<"$pr")
pr_url=$(jq -er .url <<<"$pr")
if ! run_json=$(gh run list \
  --repo "$GITHUB_REPOSITORY" \
  --workflow "$ci_workflow" \
  --event pull_request \
  --branch "$branch" \
  --commit "$head_sha" \
  --limit 1 \
  --json conclusion,databaseId,status); then
  fail "Could not query pull-request CI for trusted update $PR_NUMBER at $head_sha."
fi
jq -e '
  type == "array" and length <= 1 and
  all(.[];
    (.databaseId | type == "number") and
    (.status | type == "string") and
    (.conclusion == null or (.conclusion | type == "string")))
' <<<"$run_json" >/dev/null || fail "Pull-request CI returned malformed state for trusted update $PR_NUMBER."
run_id=$(jq -r '.[0].databaseId // empty' <<<"$run_json")
run_status=$(jq -r '.[0].status // empty' <<<"$run_json")
run_conclusion=$(jq -r '.[0].conclusion // empty' <<<"$run_json")

if [[ -z $run_id ]]; then
  complete ci-pending "Trusted update PR $PR_NUMBER is waiting for exact-head pull-request CI."
fi

if [[ $run_conclusion == action_required ]]; then
  if ! approval_error=$(gh api --method POST \
    "repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/approve" 2>&1); then
    printf '%s\n' "$approval_error" >&2
    fail "Could not approve action-required CI run $run_id for PR $PR_NUMBER at $head_sha; MERGE_QUEUE_TOKEN needs Actions write permission."
  fi
  complete ci-authorized "Authorized exact-head CI run $run_id for trusted update PR $PR_NUMBER."
fi

if [[ $run_status != completed ]]; then
  complete ci-pending "Trusted update PR $PR_NUMBER has CI run $run_id in state ${run_status:-unknown}."
fi

if [[ $run_conclusion != success ]]; then
  complete ci-blocked "Trusted update PR $PR_NUMBER is blocked by CI run $run_id (${run_conclusion:-unknown})."
fi

if [[ $APPROVAL_POLICY == trusted-maintainer ]]; then
  set +e
  has_exact_head_maintainer_approval
  approval_status=$?
  set -e
  case "$approval_status" in
    0) ;;
    1)
      complete awaiting-review "Trusted release PR $PR_NUMBER is waiting for an exact-head approval from a maintainer."
      ;;
    *) fail "Could not verify maintainer approval for trusted release PR $PR_NUMBER." ;;
  esac
fi

# Close the gap between CI/review evaluation and queue enrollment.
if ! pr=$(read_pr); then
  fail "Could not re-read trusted update PR $PR_NUMBER before queue enrollment"
fi
validate_pr "$pr"
if [[ $(jq -r '.autoMergeRequest != null' <<<"$pr") == true ]]; then
  complete queued "Trusted update PR $PR_NUMBER is already enrolled in the merge queue."
fi
if [[ $APPROVAL_POLICY == trusted-maintainer ]]; then
  set +e
  has_exact_head_maintainer_approval
  approval_status=$?
  set -e
  case "$approval_status" in
    0) ;;
    1)
      complete awaiting-review "Trusted release PR $PR_NUMBER no longer has an exact-head maintainer approval."
      ;;
    *) fail "Could not re-verify maintainer approval for trusted release PR $PR_NUMBER." ;;
  esac
fi

if ! merge_error=$(gh pr merge \
  --repo "$GITHUB_REPOSITORY" \
  --auto \
  --merge \
  --match-head-commit "$head_sha" \
  "$pr_url" 2>&1); then
  if latest_pr=$(read_pr) &&
    [[ $(jq -r '.autoMergeRequest != null' <<<"$latest_pr") == true ]]; then
    complete queued "Trusted update PR $PR_NUMBER is already enrolled in the merge queue."
  fi
  printf '%s\n' "$merge_error" >&2
  fail "Could not enroll PR $PR_NUMBER at validated head $head_sha in the merge queue; verify MERGE_QUEUE_TOKEN has Contents and Pull requests write permissions."
fi
[[ -z $merge_error ]] || printf '%s\n' "$merge_error"
complete queued "Enrolled trusted update PR $PR_NUMBER at $head_sha in the merge queue."
