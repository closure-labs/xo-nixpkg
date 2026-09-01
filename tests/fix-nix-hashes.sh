#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin" "$temporary/repository"
printf '{ }\n' >"$temporary/repository/flake.nix"

printf '#!%s\n' "$BASH" >"$temporary/bin/git"
cat >>"$temporary/bin/git" <<'EOF'
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_GIT_LOG"
case ${1:-} in
  status | check-ref-format | fetch | checkout | config | commit)
    ;;
  rev-parse)
    printf '%s\n' "$PR_HEAD_SHA"
    ;;
  diff)
    if [[ " $* " == *' --cached '* ]]; then
      [[ ! -e $FAKE_STAGED ]]
    else
      [[ ! -e $FAKE_CHANGED ]]
    fi
    ;;
  add)
    : >"$FAKE_STAGED"
    ;;
  push)
    [[ " $* " == *" --force-with-lease=refs/heads/$PR_HEAD_REF:$PR_HEAD_SHA "* ]]
    ;;
  *)
    printf 'Unexpected git command: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF

printf '#!%s\n' "$BASH" >"$temporary/bin/determinate-nixd"
cat >>"$temporary/bin/determinate-nixd" <<'EOF'
set -euo pipefail
[[ -z ${GH_TOKEN:-} && -z ${GITHUB_TOKEN:-} ]]
[[ $* == 'fix hashes --auto-apply' ]]
printf '%s\n' "$*" >>"$FAKE_DETERMINATE_LOG"
[[ $FAKE_FIX_CHANGED == false ]] || : >"$FAKE_CHANGED"
EOF

printf '#!%s\n' "$BASH" >"$temporary/bin/gh"
cat >>"$temporary/bin/gh" <<'EOF'
set -euo pipefail
[[ $GH_TOKEN == fixture-token ]]
[[ $* == 'auth setup-git' ]]
printf '%s\n' "$*" >>"$FAKE_GH_LOG"
EOF
chmod +x "$temporary/bin/git" "$temporary/bin/determinate-nixd" "$temporary/bin/gh"

head_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
run_fixer() {
  env \
    PATH="$temporary/bin:$PATH" \
    FAKE_CHANGED="$temporary/changed" \
    FAKE_DETERMINATE_LOG="$temporary/determinate.log" \
    FAKE_FIX_CHANGED="${FAKE_FIX_CHANGED:-true}" \
    FAKE_GH_LOG="$temporary/gh.log" \
    FAKE_GIT_LOG="$temporary/git.log" \
    FAKE_STAGED="$temporary/staged" \
    GH_TOKEN=fixture-token \
    GITHUB_REPOSITORY=example/xo-nixpkg \
    PR_AUTHOR="${PR_AUTHOR:-dependabot[bot]}" \
    PR_HEAD_REF=dependabot/github_actions/example \
    PR_HEAD_REPOSITORY=example/xo-nixpkg \
    PR_HEAD_SHA="$head_sha" \
    XO_NIXPKG_SOURCE_ROOT="$temporary/repository" \
      bash "$root/ci/fix-nix-hashes.sh"
}

: >"$temporary/git.log"
: >"$temporary/gh.log"
: >"$temporary/determinate.log"
run_fixer
grep -Fx 'fix hashes --auto-apply' "$temporary/determinate.log" >/dev/null
grep -Fx 'auth setup-git' "$temporary/gh.log" >/dev/null
grep -F "fetch --no-tags --depth=1 origin refs/heads/dependabot/github_actions/example" \
  "$temporary/git.log" >/dev/null
grep -F "push --force-with-lease=refs/heads/dependabot/github_actions/example:$head_sha" \
  "$temporary/git.log" >/dev/null

rm -f "$temporary/changed" "$temporary/staged"
: >"$temporary/git.log"
: >"$temporary/gh.log"
FAKE_FIX_CHANGED=false run_fixer >/dev/null
[[ ! -s $temporary/gh.log ]]
if grep -q '^commit ' "$temporary/git.log"; then
  echo 'No-op hash repair created a commit' >&2
  exit 1
fi

if PR_AUTHOR=attacker run_fixer >/dev/null 2>&1; then
  echo 'Hash fixer accepted an untrusted author' >&2
  exit 1
fi

printf 'Nix hash repair fixtures passed\n'
