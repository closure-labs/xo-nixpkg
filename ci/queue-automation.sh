#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${DEFAULT_BRANCH:?DEFAULT_BRANCH must be set}"
: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

update_author=${UPDATE_AUTHOR:-github-actions[bot]}
pull_requests=$(gh api --paginate \
  "repos/${GITHUB_REPOSITORY}/pulls?state=open&per_page=100" \
  --slurp)

jq -c \
  --arg branch "$DEFAULT_BRANCH" \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg update_author "$update_author" '
    add[] |
    select(.draft == false) |
    select(.head.repo.full_name == $repository) |
    select(.base.ref == $branch) |
    select(
      (.user.login == "dependabot[bot]" and (.head.ref | startswith("dependabot/github_actions/"))) or
      (.user.login == $update_author and .head.ref == "automation/weekly-flake-input-refresh" and .title == "flake.lock: refresh nixpkgs") or
      (.user.login == $update_author and (.head.ref | test("^update/xen-orchestra-ce-[0-9]+(\\.[0-9]+)+$")) and .title == ("xen-orchestra-ce: update to " + (.head.ref | capture("^update/xen-orchestra-ce-(?<version>.+)$").version))) or
      (.user.login == $update_author and (.head.ref | test("^update/libvhdi-[0-9]{8}$")) and .title == (.head.ref | sub("^update/libvhdi-"; "libvhdi: update to ")))
    ) |
    {author:.user.login,branch:.head.ref,number,title,sha:.head.sha}
  ' <<<"$pull_requests" |
while IFS= read -r pull_request; do
  export PR_NUMBER EXPECTED_BRANCH EXPECTED_TITLE EXPECTED_AUTHOR EXPECTED_HEAD_SHA
  PR_NUMBER=$(jq -er .number <<<"$pull_request")
  EXPECTED_BRANCH=$(jq -er .branch <<<"$pull_request")
  EXPECTED_TITLE=$(jq -er .title <<<"$pull_request")
  EXPECTED_AUTHOR=$(jq -er .author <<<"$pull_request")
  EXPECTED_HEAD_SHA=$(jq -er .sha <<<"$pull_request")
  "${XO_NIXPKG_SOURCE_ROOT:-$PWD}/ci/trusted-update.sh"
done
