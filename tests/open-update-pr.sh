#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin"
real_git=$(command -v git)

printf '#!%s\n' "$BASH" >"$temporary/bin/git"
cat >>"$temporary/bin/git" <<'EOF'
set -euo pipefail
case ${1:-} in
  ls-remote)
    exit 0
    ;;
  push)
    count=0
    [[ ! -f $FAKE_PUSH_COUNT ]] || count=$(<"$FAKE_PUSH_COUNT")
    ((count += 1))
    printf '%s\n' "$count" >"$FAKE_PUSH_COUNT"
    if ((count <= FAKE_PUSH_FAILURES)); then
      echo 'fatal: unable to access repository: HTTP 502 Bad Gateway' >&2
      exit 128
    fi
    exit 0
    ;;
  *) exec "$REAL_GIT" "$@" ;;
esac
EOF

printf '#!%s\n' "$BASH" >"$temporary/bin/gh"
cat >>"$temporary/bin/gh" <<'EOF'
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_GH_LOG"
case "$1 $2" in
  'pr list') printf '{}\n' ;;
  'pr create') printf 'https://example.invalid/pull/1\n' ;;
  *) printf 'unexpected gh call: %s\n' "$*" >&2; exit 1 ;;
esac
EOF
chmod +x "$temporary/bin/git" "$temporary/bin/gh"

make_repository() {
  local repository=$1
  mkdir -p "$repository"
  git -C "$repository" init -q
  git -C "$repository" config user.name fixture
  git -C "$repository" config user.email fixture@example.invalid
  printf 'before\n' >"$repository/update"
  git -C "$repository" add update
  git -C "$repository" commit -qm base
  git -C "$repository" remote add origin https://example.invalid/repository.git
  printf 'after\n' >"$repository/update"
}

run_fixture() {
  local repository=$1 failures=$2 push_count=$3 gh_log=$4
  (
    cd "$repository"
    env \
      PATH="$temporary/bin:$PATH" \
      REAL_GIT="$real_git" \
      FAKE_PUSH_COUNT="$push_count" \
      FAKE_PUSH_FAILURES="$failures" \
      FAKE_GH_LOG="$gh_log" \
      GH_TOKEN=fixture \
      GITHUB_REPOSITORY=example/xo-nixpkg \
      UPDATE_BRANCH=automation/test \
      UPDATE_TITLE='Fixture update' \
      UPDATE_BODY='Fixture body' \
      XO_NIXPKG_RETRY_DELAY_SECONDS=0 \
      bash "$root/ci/open-update-pr.sh" update
  )
}

transient_repository=$temporary/transient
transient_push_count=$temporary/transient-push-count
transient_gh_log=$temporary/transient-gh-log
make_repository "$transient_repository"
: >"$transient_gh_log"
run_fixture "$transient_repository" 1 "$transient_push_count" "$transient_gh_log"
[[ $(<"$transient_push_count") == 2 ]]
[[ $(grep -c '^pr create ' "$transient_gh_log") == 1 ]]

persistent_repository=$temporary/persistent
persistent_push_count=$temporary/persistent-push-count
persistent_gh_log=$temporary/persistent-gh-log
make_repository "$persistent_repository"
: >"$persistent_gh_log"
if run_fixture "$persistent_repository" 99 "$persistent_push_count" "$persistent_gh_log" \
  >"$temporary/persistent.stdout" 2>"$temporary/persistent.stderr"; then
  echo 'Persistent update-branch push failure was accepted' >&2
  exit 1
fi
[[ $(<"$persistent_push_count") == 3 ]]
[[ ! -s $persistent_gh_log ]]
grep -F 'failed after 3 attempt(s)' "$temporary/persistent.stderr" >/dev/null

printf 'Update pull-request retry fixtures passed\n'
