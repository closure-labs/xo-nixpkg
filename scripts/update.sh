#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=${XO_NIXPKG_SOURCE_ROOT:-$(cd "$script_dir/.." && pwd)}
pin_file=${XO_NIXPKG_XO_PIN_FILE:-$repo_root/nix/sources/xen-orchestra.json}
flake_file=${XO_NIXPKG_FLAKE_FILE:-$repo_root/flake.nix}
mode=release
upstream_remote=${XO_NIXPKG_UPSTREAM_REMOTE:-https://github.com/vatesfr/xen-orchestra.git}
upstream_ref=${XO_NIXPKG_UPSTREAM_REF:-refs/heads/master}
upstream_rev=${XO_NIXPKG_UPSTREAM_REV:-}
upstream_date=${XO_NIXPKG_UPSTREAM_DATE:-}
release_scan_pages=${XO_NIXPKG_RELEASE_SCAN_PAGES:-5}

usage() {
  cat <<EOF
Usage: $0 [--release|--rolling]

Modes:
  --release  Refresh latest and stable from the two newest official XO releases.
  --rolling  Refresh rolling from the current upstream master commit.
EOF
}

retry() {
  local max_attempts=$1
  shift
  local attempt
  for attempt in $(seq 1 "$max_attempts"); do
    if "$@"; then
      return 0
    fi
    if (( attempt == max_attempts )); then
      printf 'Command failed after %s attempts: %s\n' "$attempt" "$*" >&2
      return 1
    fi
    printf 'Retrying network operation (attempt %s failed): %s\n' "$attempt" "$*" >&2
    sleep $((attempt * 5))
  done
}

github_api() {
  local url=$1
  local args=(--fail --location --silent --show-error
    --header 'Accept: application/vnd.github+json'
    --header 'X-GitHub-Api-Version: 2022-11-28')
  if [[ -n ${GITHUB_TOKEN:-} ]]; then
    args+=(--header "Authorization: Bearer $GITHUB_TOKEN")
  fi
  curl "${args[@]}" "$url"
}

select_releases() {
  jq -ce '
    [
      .[]
      | .commit.message as $message
      | ($message | split("\n")[0]) as $subject
      | ($subject | capture("^feat: release (XO )?(?<version>[0-9]+(\\.[0-9]+)+)( \\(#[0-9]+\\))?$")?) as $release
      | select($release != null)
      | {sha: .sha, subject: $subject, version: $release.version}
    ]
    | unique_by(.version)
    | sort_by(.version | split(".") | map(tonumber))
    | reverse
    | .[0:2]
  '
}

find_latest_releases() {
  local fixture=${XO_NIXPKG_COMMITS_JSON:-}
  local page selected temporary combined response next
  if [[ -n $fixture ]]; then
    jq -e 'type == "array"' "$fixture" >/dev/null
    selected=$(select_releases <"$fixture")
    [[ $(jq -r length <<<"$selected") == 2 ]] || return 1
    printf '%s\n' "$selected"
    return
  fi

  temporary=$(mktemp -d)
  combined=$temporary/combined.json
  response=$temporary/response.json
  next=$temporary/next.json
  printf '[]\n' >"$combined"
  for page in $(seq 1 "$release_scan_pages"); do
    printf 'Scanning root CHANGELOG.md commits page %s for XO releases...\n' "$page" >&2
    if ! retry 3 github_api "https://api.github.com/repos/vatesfr/xen-orchestra/commits?path=CHANGELOG.md&per_page=100&page=$page" >"$response"; then
      rm -rf "$temporary"
      return 1
    fi
    if ! jq -e 'type == "array"' "$response" >/dev/null; then
      printf 'GitHub commits page %s is not a JSON array\n' "$page" >&2
      rm -rf "$temporary"
      return 1
    fi
    [[ $(jq -r length "$response") != 0 ]] || break
    jq -cs 'add' "$combined" "$response" >"$next"
    mv "$next" "$combined"
    selected=$(select_releases <"$combined")
    if [[ $(jq -r length <<<"$selected") == 2 ]]; then
      rm -rf "$temporary"
      printf '%s\n' "$selected"
      return
    fi
  done
  rm -rf "$temporary"
  return 1
}

prefetch_source() {
  local rev=$1 owner repo url
  owner=$(jq -er .owner "$pin_file")
  repo=$(jq -er .repo "$pin_file")
  url="https://github.com/$owner/$repo/archive/$rev.tar.gz"
  if [[ -n ${XO_NIXPKG_PREFETCH_JSON:-} ]]; then
    cat "$XO_NIXPKG_PREFETCH_JSON"
  else
    retry 3 nix store prefetch-file --json --unpack "$url"
  fi
}

prefetch_yarn_hash() {
  local yarn_lock=$1 normalized=$2 output status hash
  set +e
  output=$(nix-build \
    --no-out-link \
    "$repo_root/nix/prefetch-yarn-deps.nix" \
    --argstr nixpkgsPath "$XO_NIXPKG_NIXPKGS_PATH" \
    --argstr yarnLock "$yarn_lock" \
    --arg normalized "$normalized" \
    2>&1)
  status=$?
  set -e
  if (( status == 0 )); then
    echo 'Unexpectedly resolved Yarn dependencies with the placeholder hash' >&2
    return 1
  fi
  hash=$(sed -n 's/^[[:space:]]*got:[[:space:]]*\(sha256-[A-Za-z0-9+/=]*\).*/\1/p' <<<"$output" | head -n 1)
  if [[ -z $hash ]]; then
    echo 'Failed to extract the Yarn dependency hash' >&2
    tail -n 80 <<<"$output" >&2
    return 1
  fi
  printf '%s\n' "$hash"
}

source_path_from_prefetch() {
  jq -er '.storePath | select(type == "string")'
}

release_versions_match() {
  local release_version=$1 changelog_version=$2
  while [[ $release_version == *.*.0 ]]; do
    release_version=${release_version%.0}
  done
  while [[ $changelog_version == *.*.0 ]]; do
    changelog_version=${changelog_version%.0}
  done
  [[ $release_version == "$changelog_version" ]]
}

release_source() {
  local version=$1 rev=$2 source_path changelog_version
  source_path=$(prefetch_source "$rev" | source_path_from_prefetch)
  changelog_version=$(sed -nE 's/^## \*\*([0-9]+(\.[0-9]+)+)\*\*.*/\1/p' "$source_path/CHANGELOG.md" | head -n 1)
  release_versions_match "$version" "$changelog_version" || {
    printf 'Release marker %s does not match root changelog version %s\n' "$version" "${changelog_version:-missing}" >&2
    return 1
  }
  printf '%s\n' "$source_path"
}

channel_for_rev() {
  local rev=$1
  jq -cer --arg rev "$rev" '.channels | to_entries[] | select(.value.rev == $rev) | .value' "$pin_file" | head -n 1
}

channel_json() {
  local version=$1 rev=$2 source_path=${3:-} baseline=${4:-} baseline_channel=${5:-latest}
  local existing yarn_hash docs_yarn_hash
  if existing=$(channel_for_rev "$rev"); then
    jq -cn --arg version "$version" --arg rev "$rev" --argjson existing "$existing" \
      '{version:$version,rev:$rev,yarnHash:$existing.yarnHash,docsYarnHash:$existing.docsYarnHash}'
    return
  fi

  [[ -n $source_path ]] || {
    source_path=$(prefetch_source "$rev" | source_path_from_prefetch)
  }
  [[ -f $source_path/yarn.lock && -f $source_path/docs/yarn.lock ]] || {
    echo 'Prefetched XO source is missing a required Yarn lock' >&2
    return 1
  }

  yarn_hash=
  docs_yarn_hash=
  if [[ -n $baseline && -f $baseline/yarn.lock ]] && cmp -s "$baseline/yarn.lock" "$source_path/yarn.lock"; then
    yarn_hash=$(jq -er --arg channel "$baseline_channel" '.channels[$channel].yarnHash' "$pin_file")
  fi
  if [[ -n $baseline && -f $baseline/docs/yarn.lock ]] && cmp -s "$baseline/docs/yarn.lock" "$source_path/docs/yarn.lock"; then
    docs_yarn_hash=$(jq -er --arg channel "$baseline_channel" '.channels[$channel].docsYarnHash' "$pin_file")
  fi
  if [[ -z $yarn_hash || -z $docs_yarn_hash ]]; then
    [[ -n ${XO_NIXPKG_NIXPKGS_PATH:-} ]] || {
      echo 'XO_NIXPKG_NIXPKGS_PATH is required when a Yarn lock changes' >&2
      return 1
    }
  fi
  [[ -n $yarn_hash ]] || yarn_hash=$(prefetch_yarn_hash "$source_path/yarn.lock" true)
  [[ -n $docs_yarn_hash ]] || docs_yarn_hash=$(prefetch_yarn_hash "$source_path/docs/yarn.lock" false)
  jq -cn --arg version "$version" --arg rev "$rev" \
    --arg yarnHash "$yarn_hash" --arg docsYarnHash "$docs_yarn_hash" \
    '{version:$version,rev:$rev,yarnHash:$yarnHash,docsYarnHash:$docsYarnHash}'
}

update_flake_input() {
  local input=$1 rev=$2 temporary
  temporary=$(mktemp "$(dirname "$flake_file")/.flake.nix.XXXXXX")
  awk -v input="$input" -v rev="$rev" '
    $0 ~ "^    " input " = \\{" { inInput = 1 }
    inInput && $0 ~ /url = "github:vatesfr\/xen-orchestra\/[a-f0-9]+";/ {
      sub(/[a-f0-9]{40}";/, rev "\";")
      inInput = 0
    }
    { print }
  ' "$flake_file" >"$temporary"
  if cmp -s "$flake_file" "$temporary"; then
    rm -f "$temporary"
  else
    mv "$temporary" "$flake_file"
  fi
}

for argument in "$@"; do
  case "$argument" in
    --release) mode=release ;;
    --rolling | --upstream) mode=rolling ;;
    -h | --help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$argument" >&2; usage >&2; exit 2 ;;
  esac
done

cd "$repo_root"
jq -e '
  .schemaVersion == 2 and
  (.channels | keys == ["latest", "rolling", "stable"]) and
  all(.channels[];
    (.rev | test("^[a-f0-9]{40}$")) and
    (.yarnHash | startswith("sha256-")) and
    (.docsYarnHash | startswith("sha256-")))
' "$pin_file" >/dev/null

if [[ $mode == release ]]; then
  releases=$(find_latest_releases) || {
    printf 'Could not find the two newest official XO releases in %s page(s)\n' "$release_scan_pages" >&2
    exit 1
  }
  latest_version=$(jq -er '.[0].version' <<<"$releases")
  latest_rev=$(jq -er '.[0].sha' <<<"$releases")
  stable_version=$(jq -er '.[1].version' <<<"$releases")
  stable_rev=$(jq -er '.[1].sha' <<<"$releases")
  current_latest_rev=$(jq -er '.channels.latest.rev' "$pin_file")
  current_stable_rev=$(jq -er '.channels.stable.rev' "$pin_file")
  current_latest_version=$(jq -er '.channels.latest.version' "$pin_file")
  highest=$(printf '%s\n%s\n' "$current_latest_version" "$latest_version" | sort -V | tail -n 1)
  if [[ $highest != "$latest_version" ]]; then
    printf 'Refusing to downgrade latest XO from %s to %s\n' "$current_latest_version" "$latest_version" >&2
    exit 1
  fi
  latest_changed=false
  stable_changed=false
  [[ $latest_rev == "$current_latest_rev" ]] || latest_changed=true
  [[ $stable_rev == "$current_stable_rev" ]] || stable_changed=true
  if [[ $latest_changed == false && $stable_changed == false ]]; then
    printf 'Official XO channels are current: latest %s, stable %s\n' "$latest_version" "$stable_version"
    exit 0
  fi

  if [[ $latest_changed == true ]]; then
    latest_baseline=${XO_NIXPKG_CURRENT_LATEST_SOURCE:-${XO_NIXPKG_CURRENT_SOURCE:-}}
    if [[ -z $latest_baseline ]]; then
      latest_baseline=$(nix eval --accept-flake-config --raw '.#latest.src.outPath')
    fi
    latest_source=
    if ! channel_for_rev "$latest_rev" >/dev/null; then
      latest_source=$(release_source "$latest_version" "$latest_rev")
    fi
    latest_json=$(channel_json "$latest_version" "$latest_rev" "$latest_source" "$latest_baseline" latest)
  fi
  if [[ $stable_changed == true ]]; then
    stable_baseline=${XO_NIXPKG_CURRENT_STABLE_SOURCE:-${XO_NIXPKG_CURRENT_SOURCE:-}}
    if [[ -z $stable_baseline ]]; then
      stable_baseline=$(nix eval --accept-flake-config --raw '.#stable.src.outPath')
    fi
    stable_source=
    if ! channel_for_rev "$stable_rev" >/dev/null; then
      stable_source=$(release_source "$stable_version" "$stable_rev")
    fi
    stable_json=$(channel_json "$stable_version" "$stable_rev" "$stable_source" "$stable_baseline" stable)
  fi
  temporary=$(mktemp "$(dirname "$pin_file")/.xen-orchestra.json.XXXXXX")
  cp "$pin_file" "$temporary"
  if [[ $latest_changed == true ]]; then
    next=$(mktemp "$(dirname "$pin_file")/.xen-orchestra.json.XXXXXX")
    jq --argjson channel "$latest_json" '.channels.latest = $channel' "$temporary" >"$next"
    mv "$next" "$temporary"
    update_flake_input xo-latest "$latest_rev"
  fi
  if [[ $stable_changed == true ]]; then
    next=$(mktemp "$(dirname "$pin_file")/.xen-orchestra.json.XXXXXX")
    jq --argjson channel "$stable_json" '.channels.stable = $channel' "$temporary" >"$next"
    mv "$next" "$temporary"
    update_flake_input xo-stable "$stable_rev"
  fi
  mv "$temporary" "$pin_file"
  printf 'Updated official XO channels:'
  [[ $latest_changed == false ]] || printf ' latest %s (%s)' "$latest_version" "$latest_rev"
  [[ $stable_changed == false ]] || printf ' stable %s (%s)' "$stable_version" "$stable_rev"
  printf '\n'
else
  if [[ -z $upstream_rev ]]; then
    upstream_rev=$(retry 3 git ls-remote "$upstream_remote" "$upstream_ref" | awk 'NR == 1 { print $1 }')
  fi
  [[ $upstream_rev =~ ^[a-f0-9]{40}$ ]] || { echo 'Failed to resolve upstream ref' >&2; exit 1; }
  current_rev=$(jq -er '.channels.rolling.rev' "$pin_file")
  if [[ $upstream_rev == "$current_rev" ]]; then
    printf 'Rolling XO channel is current at %s\n' "$current_rev"
    exit 0
  fi
  if [[ -z $upstream_date ]]; then
    owner=$(jq -er .owner "$pin_file")
    repo=$(jq -er .repo "$pin_file")
    upstream_date=$(retry 3 github_api "https://api.github.com/repos/$owner/$repo/commits/$upstream_rev" | jq -er '.commit.committer.date[0:10]')
  fi
  [[ $upstream_date =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo 'Invalid upstream commit date' >&2; exit 1; }
  baseline=${XO_NIXPKG_CURRENT_SOURCE:-}
  if [[ -z $baseline ]]; then
    baseline=$(nix eval --accept-flake-config --raw '.#rolling.src.outPath')
  fi
  source_path=$(prefetch_source "$upstream_rev" | source_path_from_prefetch)
  rolling_json=$(channel_json "unstable-$upstream_date" "$upstream_rev" "$source_path" "$baseline" rolling)
  temporary=$(mktemp "$(dirname "$pin_file")/.xen-orchestra.json.XXXXXX")
  jq --argjson rolling "$rolling_json" '.channels.rolling = $rolling' "$pin_file" >"$temporary"
  mv "$temporary" "$pin_file"
  update_flake_input xo-rolling "$upstream_rev"
  printf 'Updated rolling XO channel to %s (%s)\n' "unstable-$upstream_date" "$upstream_rev"
fi
