#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/flake-plan-runner-test.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT

fake_nix=$temporary/nix
printf '#!%s\n' "$(command -v bash)" >"$fake_nix"
cat >>"$fake_nix" <<'EOF'
set -euo pipefail
command=$1
shift
printf '%s\n' "$command $*" >>"$FAKE_NIX_LOG"
case "$command" in
  eval)
    cat "$FAKE_NIX_PLAN"
    ;;
  build)
    installable=${!#}
    [[ $installable != *checks.x86_64-linux.failing ]]
    printf '/nix/store/%s\n' "${installable##*.}"
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$fake_nix"

cat >"$temporary/plan.json" <<'EOF'
{
  "schemaVersion": 2,
  "name": "fixture",
  "targets": [
    {"name":"first","attribute":"checks.x86_64-linux.first","link":"result-first"},
    {"name":"failing","attribute":"checks.x86_64-linux.failing"},
    {"name":"last","attribute":"packages.x86_64-linux.last"}
  ]
}
EOF

: >"$temporary/nix.log"
if FLAKE_PLAN_RUNNER_NIX="$fake_nix" \
  FLAKE_PLAN_LINK_ROOT="$temporary" \
  FAKE_NIX_LOG="$temporary/nix.log" \
  FAKE_NIX_PLAN="$temporary/plan.json" \
  bash "$root/nix/flake-plan-runner.sh" \
    --flake path:/fixture \
    --plan lib.ciPlans.x86_64-linux.fixture \
    --manifest "$temporary/manifest.json"; then
  printf 'Runner accepted a failed attribute build\n' >&2
  exit 1
fi

[[ $(grep -c '^eval ' "$temporary/nix.log") -eq 1 ]]
[[ $(grep -c '^build ' "$temporary/nix.log") -eq 3 ]]
[[ ! -e "$temporary/result-first" ]]
jq -e '
  .schemaVersion == 2 and .plan == "fixture" and .targetCount == 3 and
  .failureCount == 1 and [.results[].status] == ["success","failure","success"] and
  .results[0].outputs == ["/nix/store/first"]
' "$temporary/manifest.json" >/dev/null

jq '.targets |= map(select(.name != "failing"))' \
  "$temporary/plan.json" >"$temporary/success.json"
: >"$temporary/nix.log"
FAKE_NIX_PLAN="$temporary/success.json" \
  FAKE_NIX_LOG="$temporary/nix.log" \
  FLAKE_PLAN_LINK_ROOT="$temporary" \
  FLAKE_PLAN_RUNNER_NIX="$fake_nix" \
  bash "$root/nix/flake-plan-runner.sh" \
    --plan lib.ciPlans.x86_64-linux.fixture \
    --manifest "$temporary/success-manifest.json"
[[ $(readlink "$temporary/result-first") == /nix/store/first ]]

: >"$temporary/nix.log"
FAKE_NIX_PLAN="$temporary/success.json" \
  FAKE_NIX_LOG="$temporary/nix.log" \
  FLAKE_PLAN_LINK_ROOT="$temporary" \
  FLAKE_PLAN_RUNNER_NIX="$fake_nix" \
  bash "$root/nix/flake-plan-runner.sh" \
    --plan-file "$temporary/success.json" \
    --manifest "$temporary/direct-manifest.json"
[[ $(grep -c '^eval ' "$temporary/nix.log" || true) -eq 0 ]]
jq -e '.targetCount == 2 and .failureCount == 0' \
  "$temporary/direct-manifest.json" >/dev/null

jq '.targets[1].name = .targets[0].name' \
  "$temporary/success.json" >"$temporary/malformed.json"
: >"$temporary/nix.log"
if FAKE_NIX_PLAN="$temporary/malformed.json" \
  FAKE_NIX_LOG="$temporary/nix.log" \
  FLAKE_PLAN_RUNNER_NIX="$fake_nix" \
  bash "$root/nix/flake-plan-runner.sh" \
    --plan lib.ciPlans.x86_64-linux.fixture; then
  printf 'Runner accepted a malformed plan\n' >&2
  exit 1
fi
[[ $(grep -c '^build ' "$temporary/nix.log" || true) -eq 0 ]]

printf 'Flake plan runner fixtures passed\n'
