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
    --arg author "${FAKE_AUTHOR:-app/nixoa-updater}" \
    --arg repository "${FAKE_REPOSITORY:-example/xo-nixpkg}" \
    '{author:{login:$author},baseRefName:"main",headRefName:"automation/test",headRefOid:"abc123",headRepository:{nameWithOwner:$repository},mergeStateStatus:"CLEAN",state:"OPEN",title:"Trusted update",url:"https://example.invalid/pr/1"}'
elif [[ "$1 $2" == 'run list' ]]; then
  printf '42\n'
elif [[ "$1 $2" == 'pr merge' ]]; then
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
  EXPECTED_AUTHOR=nixoa-updater
  EXPECTED_HEAD_SHA=abc123
  DEFAULT_BRANCH=main
  FAKE_MERGE_LOG="$temporary/merge.log"
)

env PATH="$temporary/bin:$PATH" "${trusted_env[@]}" bash "$root/ci/trusted-update.sh"
grep -Fq -- '--match-head-commit abc123' "$temporary/merge.log"

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
