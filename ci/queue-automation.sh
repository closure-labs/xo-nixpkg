#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${DEFAULT_BRANCH:?DEFAULT_BRANCH must be set}"
: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

update_author=${UPDATE_AUTHOR:-github-actions}
trusted_update=${XO_NIXPKG_TRUSTED_UPDATE_COMMAND:-xo-nixpkg-trusted-update}
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT

pull_requests=$(gh api --paginate \
  "repos/${GITHUB_REPOSITORY}/pulls?state=open&per_page=100" \
  --slurp)

if ! candidates_json=$(jq -c \
    --arg branch "$DEFAULT_BRANCH" \
    --arg repository "$GITHUB_REPOSITORY" \
    --arg update_author "$update_author" '
      [
      add[] |
      select(.draft == false) |
      select(.head.repo.full_name == $repository) |
      select(.base.ref == $branch) |
      ((.user.login // "") | sub("\\[bot\\]$"; "")) as $author |
      if $author == "dependabot" and (.head.ref | startswith("dependabot/github_actions/")) then
        {author:$author,branch:.head.ref,number,title,sha:.head.sha,
         kind:"dependabot-actions",approvalPolicy:"automatic"}
      elif $author == $update_author and
        .head.ref == "automation/weekly-flake-input-refresh" and
        .title == "flake.lock: refresh nixpkgs" then
        {author:$author,branch:.head.ref,number,title,sha:.head.sha,
         kind:"flake-lock",approvalPolicy:"automatic"}
      elif $author == $update_author and
        .head.ref == "automation/xo-release-channels" and
        .title == "xen-orchestra-ce channels: refresh official releases" then
        {author:$author,branch:.head.ref,number,title,sha:.head.sha,
         kind:"xo-release",approvalPolicy:"trusted-maintainer"}
      elif $author == $update_author and
        (.head.ref | test("^automation/xo-release-[0-9]+(\\.[0-9]+)+$")) and
        .title == ("xen-orchestra-ce: update to " + (.head.ref | sub("^automation/xo-release-"; ""))) then
        {author:$author,branch:.head.ref,number,title,sha:.head.sha,
         kind:"xo-release",approvalPolicy:"trusted-maintainer"}
      elif $author == $update_author and
        .head.ref == "automation/xo-rolling" and
        .title == "xen-orchestra-ce rolling: refresh upstream" then
        {author:$author,branch:.head.ref,number,title,sha:.head.sha,
         kind:"xo-rolling",approvalPolicy:"automatic"}
      elif $author == $update_author and
        (.head.ref | test("^update/libvhdi-[0-9]{8}$")) and
        .title == (.head.ref | sub("^update/libvhdi-"; "libvhdi: update to ")) then
        {author:$author,branch:.head.ref,number,title,sha:.head.sha,
         kind:"libvhdi",approvalPolicy:"automatic"}
      else empty
      end
      ]
    ' <<<"$pull_requests"); then
  echo 'Could not classify the open pull-request response.' >&2
  exit 1
fi
mapfile -t candidates < <(jq -c '.[]' <<<"$candidates_json")

validate_candidate_paths() {
  local kind=$1 files=$2
  case "$kind" in
    xo-release | xo-rolling)
      jq -e '
        [add[].filename] | sort | unique ==
        (["flake.lock", "flake.nix", "nix/sources/xen-orchestra.json"] | sort)
      ' <<<"$files" >/dev/null
      ;;
    flake-lock)
      jq -e '[add[].filename] | sort | unique == ["flake.lock"]' \
        <<<"$files" >/dev/null
      ;;
    libvhdi)
      jq -e '[add[].filename] | sort | unique == ["nix/sources/libvhdi.json"]' \
        <<<"$files" >/dev/null
      ;;
    dependabot-actions)
      jq -e '
        [add[].filename] as $paths |
        ($paths | length) > 0 and
        all($paths[];
          test("^\\.github/workflows/[^/]+\\.ya?ml$") or
          test("^\\.github/actions/[^/]+/action\\.ya?ml$"))
      ' <<<"$files" >/dev/null
      ;;
    *) return 1 ;;
  esac
}

summary_file=${GITHUB_STEP_SUMMARY:-}
if [[ -n $summary_file ]]; then
  printf '%s\n\n%s\n' '### Trusted update reconciliation' \
    '| PR | Kind | Result | Detail |' >>"$summary_file"
  printf '%s\n' '|---:|---|---|---|' >>"$summary_file"
fi

append_summary() {
  local number=$1 kind=$2 status=$3 message=$4
  [[ -n $summary_file ]] || return 0
  message=${message//$'\n'/ }
  message=${message//|/\\|}
  # Backticks are intentional Markdown code delimiters, not shell expansion.
  # shellcheck disable=SC2016
  printf '| #%s | %s | `%s` | %s |\n' \
    "$number" "$kind" "$status" "$message" >>"$summary_file"
}

failure_count=0
for candidate in "${candidates[@]}"; do
  PR_NUMBER=$(jq -er .number <<<"$candidate")
  EXPECTED_BRANCH=$(jq -er .branch <<<"$candidate")
  EXPECTED_TITLE=$(jq -er .title <<<"$candidate")
  EXPECTED_AUTHOR=$(jq -er .author <<<"$candidate")
  EXPECTED_HEAD_SHA=$(jq -er .sha <<<"$candidate")
  APPROVAL_POLICY=$(jq -er .approvalPolicy <<<"$candidate")
  kind=$(jq -er .kind <<<"$candidate")

  if ! files=$(gh api --paginate \
    "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100" \
    --slurp); then
    message="Could not read changed files for trusted update PR $PR_NUMBER."
    printf '%s\n' "$message" >&2
    append_summary "$PR_NUMBER" "$kind" policy-error "$message"
    ((failure_count += 1))
    continue
  fi
  if ! validate_candidate_paths "$kind" "$files"; then
    message="Trusted update PR $PR_NUMBER violates the $kind changed-file policy."
    printf '%s\n' "$message" >&2
    append_summary "$PR_NUMBER" "$kind" policy-error "$message"
    ((failure_count += 1))
    continue
  fi

  result_file=$temporary/result-$PR_NUMBER.json
  if output=$(env \
    APPROVAL_POLICY="$APPROVAL_POLICY" \
    DEFAULT_BRANCH="$DEFAULT_BRANCH" \
    EXPECTED_AUTHOR="$EXPECTED_AUTHOR" \
    EXPECTED_BRANCH="$EXPECTED_BRANCH" \
    EXPECTED_HEAD_SHA="$EXPECTED_HEAD_SHA" \
    EXPECTED_TITLE="$EXPECTED_TITLE" \
    GH_TOKEN="$GH_TOKEN" \
    GITHUB_REPOSITORY="$GITHUB_REPOSITORY" \
    PR_NUMBER="$PR_NUMBER" \
    TRUSTED_UPDATE_RESULT_FILE="$result_file" \
    "$trusted_update" 2>&1); then
    printf '%s\n' "$output"
    status=$(jq -r '.status // "policy-error"' "$result_file")
    message=$(jq -r '.message // "Trusted update returned no detail"' "$result_file")
    append_summary "$PR_NUMBER" "$kind" "$status" "$message"
  else
    printf '%s\n' "$output" >&2
    status=policy-error
    message="Trusted update reconciliation failed."
    if [[ -s $result_file ]]; then
      message=$(jq -r '.message // "Trusted update reconciliation failed."' "$result_file")
    fi
    append_summary "$PR_NUMBER" "$kind" "$status" "$message"
    ((failure_count += 1))
  fi
done

if ((failure_count > 0)); then
  printf 'Trusted update reconciliation encountered %s policy or infrastructure error(s).\n' \
    "$failure_count" >&2
  exit 1
fi

printf 'Trusted update reconciliation completed for %s candidate(s).\n' \
  "${#candidates[@]}"
