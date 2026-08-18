#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/flake-attribute-validator-test.XXXXXX")
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
    ;;
  *)
    exit 2
    ;;
esac
EOF
chmod +x "$fake_nix"

cat >"$temporary/plan.json" <<'EOF'
{
  "schemaVersion": 1,
  "name": "fixture",
  "targets": [
    {"name": "first", "attribute": "checks.x86_64-linux.first"},
    {"name": "failing", "attribute": "checks.x86_64-linux.failing"},
    {"name": "last", "attribute": "packages.x86_64-linux.last"}
  ]
}
EOF

: >"$temporary/nix.log"
if FLAKE_ATTRIBUTE_VALIDATOR_NIX="$fake_nix" \
  FAKE_NIX_LOG="$temporary/nix.log" \
  FAKE_NIX_PLAN="$temporary/plan.json" \
  bash "$root/nix/flake-attribute-validator.sh" \
    --flake path:/fixture \
    --plan lib.ciPlans.x86_64-linux.fixture \
    --summary "$temporary/summary.json"; then
  printf 'Validator accepted a failed attribute build\n' >&2
  exit 1
fi

[[ $(grep -c '^eval ' "$temporary/nix.log") -eq 1 ]]
[[ $(grep -c '^build ' "$temporary/nix.log") -eq 3 ]]
grep -Fq 'checks.x86_64-linux.first' "$temporary/nix.log"
grep -Fq 'checks.x86_64-linux.failing' "$temporary/nix.log"
grep -Fq 'packages.x86_64-linux.last' "$temporary/nix.log"
jq -e '
  .schemaVersion == 1 and
  .plan == "fixture" and
  .targetCount == 3 and
  .failureCount == 1 and
  [.results[].status] == ["success", "failure", "success"]
' "$temporary/summary.json" >/dev/null

cat >"$temporary/malformed.json" <<'EOF'
{
  "schemaVersion": 1,
  "name": "fixture",
  "targets": [
    {"name": "duplicate", "attribute": "checks.x86_64-linux.first"},
    {"name": "duplicate", "attribute": "checks.x86_64-linux.second"}
  ]
}
EOF

: >"$temporary/nix.log"
if FLAKE_ATTRIBUTE_VALIDATOR_NIX="$fake_nix" \
  FAKE_NIX_LOG="$temporary/nix.log" \
  FAKE_NIX_PLAN="$temporary/malformed.json" \
  bash "$root/nix/flake-attribute-validator.sh" \
    --plan lib.ciPlans.x86_64-linux.fixture; then
  printf 'Validator accepted a malformed plan\n' >&2
  exit 1
fi

[[ $(grep -c '^eval ' "$temporary/nix.log") -eq 1 ]]
[[ $(grep -c '^build ' "$temporary/nix.log" || true) -eq 0 ]]

printf 'Flake attribute validator fixtures passed\n'
