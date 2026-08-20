#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${DEFAULT_BRANCH:?DEFAULT_BRANCH must be set}"
: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

update_author=${UPDATE_AUTHOR:-nixoa-updater}
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
    (.user.login | sub("\\[bot\\]$"; "")) as $author |
    select(
      ($author == "dependabot" and (.head.ref | startswith("dependabot/github_actions/"))) or
      ($author == $update_author and .head.ref == "automation/weekly-flake-input-refresh" and .title == "flake.lock: refresh nixpkgs") or
      ($author == $update_author and .head.ref == "automation/xo-release-channels" and .title == "xen-orchestra-ce channels: refresh official releases") or
      ($author == $update_author and .head.ref == "automation/xo-rolling" and .title == "xen-orchestra-ce rolling: refresh upstream") or
      ($author == $update_author and (.head.ref | test("^update/libvhdi-[0-9]{8}$")) and .title == (.head.ref | sub("^update/libvhdi-"; "libvhdi: update to ")))
    ) |
    {author:$author,branch:.head.ref,number,title,sha:.head.sha}
  ' <<<"$pull_requests" |
while IFS= read -r pull_request; do
  export PR_NUMBER EXPECTED_BRANCH EXPECTED_TITLE EXPECTED_AUTHOR EXPECTED_HEAD_SHA
  PR_NUMBER=$(jq -er .number <<<"$pull_request")
  EXPECTED_BRANCH=$(jq -er .branch <<<"$pull_request")
  EXPECTED_TITLE=$(jq -er .title <<<"$pull_request")
  EXPECTED_AUTHOR=$(jq -er .author <<<"$pull_request")
  EXPECTED_HEAD_SHA=$(jq -er .sha <<<"$pull_request")
  xo-nixpkg-trusted-update
done
