#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/bin"

printf '#!%s\n' "$BASH" >"$temporary/bin/gh"
cat >>"$temporary/bin/gh" <<'EOF'
set -euo pipefail
if [[ "$1 $2" == 'pr view' ]]; then
  auto_merge=null
  [[ ${FAKE_AUTO_MERGE:-false} != true ]] || auto_merge='{"enabledAt":"2026-09-04T00:00:00Z"}'
  jq -n \
    --arg author "${FAKE_AUTHOR:-github-actions[bot]}" \
    --arg repository "${FAKE_REPOSITORY:-example/xo-nixpkg}" \
    --argjson auto_merge "$auto_merge" \
    '{author:{login:$author},autoMergeRequest:$auto_merge,baseRefName:"main",headRefName:"automation/test",headRefOid:"abc123",headRepository:{nameWithOwner:$repository},isDraft:false,state:"OPEN",title:"Trusted update",url:"https://example.invalid/pr/1"}'
elif [[ "$1 $2" == 'run list' ]]; then
  if [[ ${FAKE_RUN_MISSING:-false} == true ]]; then
    printf '[]\n'
  else
    jq -cn \
      --arg conclusion "${FAKE_RUN_CONCLUSION:-success}" \
      --arg status "${FAKE_RUN_STATUS:-completed}" \
      '[{databaseId:42,conclusion:$conclusion,status:$status}]'
  fi
elif [[ $1 == api ]]; then
  case "$*" in
    *'/pulls?'*) printf '[%s]\n' "${FAKE_PULLS_JSON:-[]}" ;;
    *'/files?'*)
      endpoint=
      for argument in "$@"; do
        [[ $argument != */pulls/*/files\?* ]] || endpoint=$argument
      done
      number=${endpoint#*/pulls/}
      number=${number%%/*}
      variable=FAKE_FILES_$number
      printf '[%s]\n' "${!variable:-[]}"
      ;;
    *'/reviews?'*) printf '[%s]\n' "${FAKE_REVIEWS_JSON:-[]}" ;;
    *'/collaborators/'*'/permission'*)
      if [[ ${FAKE_PERMISSION_ERROR:-false} == true ]]; then
        echo 'gh: Not Found (HTTP 404)' >&2
        exit 1
      fi
      printf '%s\n' "${FAKE_PERMISSION:-write}"
      ;;
    *'/actions/runs/'*'/approve'*)
      if [[ ${FAKE_APPROVE_FAILURE:-false} == true ]]; then
        echo 'GraphQL: Resource not accessible by integration' >&2
        exit 1
      fi
      printf '%s\n' "$*" >"$FAKE_APPROVE_LOG"
      ;;
    *) printf 'unexpected gh api call: %s\n' "$*" >&2; exit 1 ;;
  esac
elif [[ "$1 $2" == 'pr merge' ]]; then
  if [[ ${FAKE_MERGE_FAILURE:-false} == true ]]; then
    echo 'GraphQL: Pull request is not mergeable' >&2
    exit 1
  fi
  printf '%s\n' "$*" >"$FAKE_MERGE_LOG"
else
  printf 'unexpected gh call: %s\n' "$*" >&2
  exit 1
fi
EOF
chmod +x "$temporary/bin/gh"

trusted_env=(
  GH_TOKEN=fixture
  GITHUB_REPOSITORY=example/xo-nixpkg
  PR_NUMBER=1
  EXPECTED_BRANCH=automation/test
  EXPECTED_TITLE='Trusted update'
  EXPECTED_AUTHOR=github-actions
  EXPECTED_HEAD_SHA=abc123
  DEFAULT_BRANCH=main
  FAKE_APPROVE_LOG="$temporary/approve.log"
  FAKE_MERGE_LOG="$temporary/merge.log"
)

run_trusted() {
  local policy=$1 result=$2
  shift 2
  env PATH="$temporary/bin:$PATH" \
    APPROVAL_POLICY="$policy" \
    TRUSTED_UPDATE_RESULT_FILE="$result" \
    "${trusted_env[@]}" "$@" \
    bash "$root/ci/trusted-update.sh"
}

assert_status() {
  local expected=$1 file=$2
  [[ $(jq -er .status "$file") == "$expected" ]]
}

# Native action-required pull-request CI is authorized, then a later
# workflow_run reconciliation observes its eventual result.
run_trusted automatic "$temporary/result.json" \
  FAKE_RUN_CONCLUSION=action_required >/dev/null
assert_status ci-authorized "$temporary/result.json"
grep -Fq -- 'actions/runs/42/approve' "$temporary/approve.log"
[[ ! -e $temporary/merge.log ]]

rm -f "$temporary/approve.log" "$temporary/merge.log"
run_trusted automatic "$temporary/result.json" \
  FAKE_RUN_STATUS=in_progress FAKE_RUN_CONCLUSION='' >/dev/null
assert_status ci-pending "$temporary/result.json"
[[ ! -e $temporary/merge.log ]]

run_trusted automatic "$temporary/result.json" \
  FAKE_RUN_CONCLUSION=failure >/dev/null
assert_status ci-blocked "$temporary/result.json"
[[ ! -e $temporary/merge.log ]]

# Rolling and other automatic candidates enter the queue after exact-head CI.
run_trusted automatic "$temporary/result.json" >/dev/null
assert_status queued "$temporary/result.json"
grep -Fq -- '--match-head-commit abc123' "$temporary/merge.log"

# Versioned release updates need a current-head approval by a collaborator
# whose effective repository permission is write, maintain, or admin.
rm -f "$temporary/merge.log"
run_trusted trusted-maintainer "$temporary/result.json" >/dev/null
assert_status awaiting-review "$temporary/result.json"
[[ ! -e $temporary/merge.log ]]

# A pre-existing auto-merge request does not bypass release approval policy.
run_trusted trusted-maintainer "$temporary/result.json" \
  FAKE_AUTO_MERGE=true >/dev/null
assert_status awaiting-review "$temporary/result.json"
[[ ! -e $temporary/merge.log ]]

approval='[{"id":1,"state":"APPROVED","commit_id":"abc123","user":{"login":"maintainer"}}]'
run_trusted trusted-maintainer "$temporary/result.json" \
  FAKE_REVIEWS_JSON="$approval" >/dev/null
assert_status queued "$temporary/result.json"
grep -Fq -- '--match-head-commit abc123' "$temporary/merge.log"

rm -f "$temporary/merge.log"
stale='[{"id":1,"state":"APPROVED","commit_id":"oldsha","user":{"login":"maintainer"}}]'
run_trusted trusted-maintainer "$temporary/result.json" \
  FAKE_REVIEWS_JSON="$stale" >/dev/null
assert_status awaiting-review "$temporary/result.json"
[[ ! -e $temporary/merge.log ]]

run_trusted trusted-maintainer "$temporary/result.json" \
  FAKE_REVIEWS_JSON="$approval" FAKE_PERMISSION=read >/dev/null
assert_status awaiting-review "$temporary/result.json"
[[ ! -e $temporary/merge.log ]]

withdrawn='[
  {"id":1,"state":"APPROVED","commit_id":"abc123","user":{"login":"maintainer"}},
  {"id":2,"state":"CHANGES_REQUESTED","commit_id":"abc123","user":{"login":"maintainer"}}
]'
run_trusted trusted-maintainer "$temporary/result.json" \
  FAKE_REVIEWS_JSON="$withdrawn" >/dev/null
assert_status awaiting-review "$temporary/result.json"
[[ ! -e $temporary/merge.log ]]

if run_trusted trusted-maintainer "$temporary/result.json" \
  FAKE_REVIEWS_JSON='{"malformed":true}' >/dev/null 2>&1; then
  echo 'Trusted queue treated malformed review state as a missing approval' >&2
  exit 1
fi

if run_trusted automatic "$temporary/result.json" \
  FAKE_RUN_CONCLUSION=action_required FAKE_APPROVE_FAILURE=true \
  >"$temporary/approve.stdout" 2>"$temporary/approve.stderr"; then
  echo 'Trusted queue accepted a denied action-required workflow approval' >&2
  exit 1
fi
grep -F 'Could not approve action-required CI run 42 for PR 1 at abc123' \
  "$temporary/approve.stderr" >/dev/null
grep -F 'Actions write permission' "$temporary/approve.stderr" >/dev/null

if run_trusted automatic "$temporary/result.json" FAKE_MERGE_FAILURE=true \
  >"$temporary/merge.stdout" 2>"$temporary/merge.stderr"; then
  echo 'Trusted queue accepted an auto-merge denial' >&2
  exit 1
fi
grep -F 'Could not enroll PR 1 at validated head abc123 in the merge queue' \
  "$temporary/merge.stderr" >/dev/null

if run_trusted automatic "$temporary/result.json" FAKE_AUTHOR=attacker >/dev/null 2>&1; then
  echo 'Trusted queue accepted the wrong author' >&2
  exit 1
fi
if run_trusted automatic "$temporary/result.json" \
  FAKE_REPOSITORY=attacker/fork >/dev/null 2>&1; then
  echo 'Trusted queue accepted the wrong head repository' >&2
  exit 1
fi

# The reconciler assigns different approval policies to release and rolling
# updates, enforces changed-file allowlists, and continues after one bad PR.
printf '#!%s\n' "$BASH" >"$temporary/bin/fake-trusted-update"
cat >>"$temporary/bin/fake-trusted-update" <<'EOF'
set -euo pipefail
printf '%s %s\n' "$PR_NUMBER" "$APPROVAL_POLICY" >>"$FAKE_TRUSTED_LOG"
jq -n --arg message "fixture PR $PR_NUMBER" \
  '{status:"queued",message:$message}' >"$TRUSTED_UPDATE_RESULT_FILE"
EOF
chmod +x "$temporary/bin/fake-trusted-update"

release_pr='{
  "draft":false,"number":1,"title":"xen-orchestra-ce: update to 6.8.2",
  "user":{"login":"github-actions[bot]"},"base":{"ref":"main"},
  "head":{"ref":"automation/xo-release-6.8.2","sha":"release-sha","repo":{"full_name":"example/xo-nixpkg"}}
}'
rolling_pr='{
  "draft":false,"number":2,"title":"xen-orchestra-ce rolling: refresh upstream",
  "user":{"login":"github-actions[bot]"},"base":{"ref":"main"},
  "head":{"ref":"automation/xo-rolling","sha":"rolling-sha","repo":{"full_name":"example/xo-nixpkg"}}
}'
files='[
  {"filename":"flake.lock"},
  {"filename":"flake.nix"},
  {"filename":"nix/sources/xen-orchestra.json"}
]'
pulls="[$release_pr,$rolling_pr]"
: >"$temporary/trusted.log"
env PATH="$temporary/bin:$PATH" \
  GH_TOKEN=fixture \
  GITHUB_REPOSITORY=example/xo-nixpkg \
  DEFAULT_BRANCH=main \
  XO_NIXPKG_TRUSTED_UPDATE_COMMAND="$temporary/bin/fake-trusted-update" \
  FAKE_TRUSTED_LOG="$temporary/trusted.log" \
  FAKE_PULLS_JSON="$pulls" \
  FAKE_FILES_1="$files" \
  FAKE_FILES_2="$files" \
  GITHUB_STEP_SUMMARY="$temporary/summary.md" \
  bash "$root/ci/queue-automation.sh" >/dev/null
grep -Fx '1 trusted-maintainer' "$temporary/trusted.log" >/dev/null
grep -Fx '2 automatic' "$temporary/trusted.log" >/dev/null
# Backticks are literal Markdown generated by the reconciler.
# shellcheck disable=SC2016
grep -F '| #1 | xo-release | `queued` |' "$temporary/summary.md" >/dev/null
# shellcheck disable=SC2016
grep -F '| #2 | xo-rolling | `queued` |' "$temporary/summary.md" >/dev/null

invalid_pr=${rolling_pr/\"number\":2/\"number\":3}
invalid_pr=${invalid_pr/rolling-sha/invalid-sha}
later_pr=${rolling_pr/\"number\":2/\"number\":4}
later_pr=${later_pr/rolling-sha/later-sha}
invalid_files='[
  {"filename":"flake.lock"},
  {"filename":"flake.nix"},
  {"filename":"nix/sources/xen-orchestra.json"},
  {"filename":"ci/trusted-update.sh"}
]'
: >"$temporary/trusted.log"
if env PATH="$temporary/bin:$PATH" \
  GH_TOKEN=fixture \
  GITHUB_REPOSITORY=example/xo-nixpkg \
  DEFAULT_BRANCH=main \
  XO_NIXPKG_TRUSTED_UPDATE_COMMAND="$temporary/bin/fake-trusted-update" \
  FAKE_TRUSTED_LOG="$temporary/trusted.log" \
  FAKE_PULLS_JSON="[$invalid_pr,$later_pr]" \
  FAKE_FILES_3="$invalid_files" \
  FAKE_FILES_4="$files" \
  GITHUB_STEP_SUMMARY="$temporary/invalid-summary.md" \
  bash "$root/ci/queue-automation.sh" >/dev/null 2>&1; then
  echo 'Queue reconciler accepted a changed-file policy violation' >&2
  exit 1
fi
[[ $(wc -l <"$temporary/trusted.log") == 1 ]]
grep -Fx '4 automatic' "$temporary/trusted.log" >/dev/null
# shellcheck disable=SC2016
grep -F '| #3 | xo-rolling | `policy-error` |' \
  "$temporary/invalid-summary.md" >/dev/null
# shellcheck disable=SC2016
grep -F '| #4 | xo-rolling | `queued` |' \
  "$temporary/invalid-summary.md" >/dev/null

printf 'Trusted update fixtures passed\n'
