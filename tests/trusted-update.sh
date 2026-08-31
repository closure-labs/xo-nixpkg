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
  jq -n \
    --arg author "${FAKE_AUTHOR:-github-actions[bot]}" \
    --arg repository "${FAKE_REPOSITORY:-example/xo-nixpkg}" \
    '{author:{login:$author},baseRefName:"main",headRefName:"automation/test",headRefOid:"abc123",headRepository:{nameWithOwner:$repository},mergeStateStatus:"CLEAN",state:"OPEN",title:"Trusted update",url:"https://example.invalid/pr/1"}'
elif [[ "$1 $2" == 'run list' ]]; then
  printf '[{"databaseId":42,"conclusion":"action_required"}]\n'
elif [[ $1 == api ]]; then
  if [[ ${FAKE_APPROVE_FAILURE:-false} == true ]]; then
    echo 'GraphQL: Resource not accessible by integration' >&2
    exit 1
  fi
  printf '%s\n' "$*" >"$FAKE_APPROVE_LOG"
elif [[ "$1 $2" == 'run watch' ]]; then
  :
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

env PATH="$temporary/bin:$PATH" "${trusted_env[@]}" bash "$root/ci/trusted-update.sh"
grep -Fq -- 'actions/runs/42/approve' "$temporary/approve.log"
grep -Fq -- '--match-head-commit abc123' "$temporary/merge.log"

if env PATH="$temporary/bin:$PATH" FAKE_APPROVE_FAILURE=true "${trusted_env[@]}" \
  bash "$root/ci/trusted-update.sh" >"$temporary/approve.stdout" 2>"$temporary/approve.stderr"; then
  echo 'Trusted queue accepted a denied action-required workflow approval' >&2
  exit 1
fi
grep -F 'Could not approve action-required CI run 42 for PR 1 at abc123.' \
  "$temporary/approve.stderr" >/dev/null
grep -F 'Actions write permission' "$temporary/approve.stderr" >/dev/null

if env PATH="$temporary/bin:$PATH" FAKE_MERGE_FAILURE=true "${trusted_env[@]}" \
  bash "$root/ci/trusted-update.sh" >"$temporary/merge.stdout" 2>"$temporary/merge.stderr"; then
  echo 'Trusted queue accepted an auto-merge denial' >&2
  exit 1
fi
grep -F 'Could not enroll PR 1 at validated head abc123 in the merge queue.' \
  "$temporary/merge.stderr" >/dev/null
grep -F 'Contents and Pull requests write permissions' "$temporary/merge.stderr" >/dev/null

if env PATH="$temporary/bin:$PATH" FAKE_AUTHOR=attacker "${trusted_env[@]}" \
  bash "$root/ci/trusted-update.sh" >/dev/null 2>&1; then
  echo 'Trusted queue accepted the wrong author' >&2
  exit 1
fi
if env PATH="$temporary/bin:$PATH" FAKE_REPOSITORY=attacker/fork "${trusted_env[@]}" \
  bash "$root/ci/trusted-update.sh" >/dev/null 2>&1; then
  echo 'Trusted queue accepted the wrong head repository' >&2
  exit 1
fi
