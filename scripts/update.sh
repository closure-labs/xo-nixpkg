#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
pin_file=${XO_NIXPKG_XO_PIN_FILE:-$repo_root/nix/sources/xen-orchestra.json}
mode=release
upstream_remote=${XO_NIXPKG_UPSTREAM_REMOTE:-https://github.com/vatesfr/xen-orchestra.git}
upstream_ref=${XO_NIXPKG_UPSTREAM_REF:-refs/heads/master}
upstream_rev=${XO_NIXPKG_UPSTREAM_REV:-}
release_scan_pages=${XO_NIXPKG_RELEASE_SCAN_PAGES:-5}

usage() {
  cat <<EOF
Usage: $0 [--release|--upstream]

Modes:
  --release   Update to the latest unscoped "feat: release X.Y.Z" commit.
  --upstream  Update the source pin to upstream HEAD without changing its version.
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
    printf 'Retrying after transient failure (attempt %s failed): %s\n' "$attempt" "$*" >&2
    sleep $((attempt * 15))
  done
}

github_api() {
  local url=$1
  local args=(--fail --location --silent --show-error --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28')
  if [[ -n ${GITHUB_TOKEN:-} ]]; then
    args+=(--header "Authorization: Bearer $GITHUB_TOKEN")
  fi
  curl "${args[@]}" "$url"
}

select_release() {
  jq -cer '
    [
      .[]
      | .commit.message as $message
      | ($message | split("\n")[0]) as $subject
      | ($subject | capture("^feat: release (XO )?(?<version>[0-9]+(\\.[0-9]+)+)( \\(#[0-9]+\\))?$")?) as $release
      | select($release != null)
      | {sha: .sha, subject: $subject, version: $release.version}
    ][0] // error("no Xen Orchestra release marker found")
  '
}

find_latest_release() {
  local fixture=${XO_NIXPKG_COMMITS_JSON:-}
  local page response
  if [[ -n $fixture ]]; then
    select_release <"$fixture"
    return
  fi

  for page in $(seq 1 "$release_scan_pages"); do
    printf 'Scanning root CHANGELOG.md commits page %s for an XO release marker...\n' "$page" >&2
    response=$(retry 3 github_api "https://api.github.com/repos/vatesfr/xen-orchestra/commits?path=CHANGELOG.md&per_page=100&page=$page")
    [[ $(jq -r length <<<"$response") != 0 ]] || break
    if select_release <<<"$response" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

prefetch_source() {
  local url=$1
  if [[ -n ${XO_NIXPKG_PREFETCH_JSON:-} ]]; then
    cat "$XO_NIXPKG_PREFETCH_JSON"
  else
    retry 3 nix store prefetch-file --json --unpack "$url"
  fi
}

prefetch_yarn_hash() {
  local yarn_lock=$1
  local normalized=$2
  local output status hash

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
    printf 'Unexpectedly resolved Yarn dependencies with the placeholder hash\n' >&2
    return 1
  fi
  hash=$(sed -n 's/^[[:space:]]*got:[[:space:]]*\(sha256-[A-Za-z0-9+/=]*\).*/\1/p' <<<"$output" | head -n 1)
  if [[ -z $hash ]]; then
    printf 'Failed to extract the Yarn dependency hash\n' >&2
    tail -n 80 <<<"$output" >&2
    return 1
  fi
  printf '%s\n' "$hash"
}

lock_version() {
  local yarn_lock=$1 package=$2
  awk -v package="$package" '
    index($0, "\"" package "@") == 1 { inEntry = 1; next }
    inEntry && $1 == "version" { gsub(/"/, "", $2); print $2; exit }
    inEntry && /^$/ { inEntry = 0 }
  ' "$yarn_lock"
}

tool_json() {
  local version=$1 tarball=$2 path=$3 package_base=${4:-}
  if [[ -z $version ]]; then
    printf 'null'
  elif [[ -n $package_base ]]; then
    jq -cn --arg version "$version" --arg tarball "$tarball" --arg path "$path" --arg packageBase "$package_base" \
      '{version:$version,tarball:$tarball,path:$path,packageBase:$packageBase}'
  else
    jq -cn --arg version "$version" --arg tarball "$tarball" --arg path "$path" \
      '{version:$version,tarball:$tarball,path:$path}'
  fi
}

for argument in "$@"; do
  case "$argument" in
    --release) mode=release ;;
    --upstream) mode=upstream ;;
    -h | --help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$argument" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z ${XO_NIXPKG_UPDATE_IN_DEV_SHELL:-} ]]; then
  export XO_NIXPKG_UPDATE_IN_DEV_SHELL=1
  exec nix develop --accept-flake-config "$repo_root#updater" --command bash "$script_dir/update.sh" "--$mode"
fi

cd "$repo_root"
jq -e '
  .schemaVersion == 1 and
  (.version | test("^[0-9]+(\\.[0-9]+)+$")) and
  (.rev | test("^[a-f0-9]{40}$")) and
  (.hash | startswith("sha256-")) and
  (.yarnHash | startswith("sha256-")) and
  (.docsYarnHash | startswith("sha256-"))
' "$pin_file" >/dev/null

current_version=$(jq -er .version "$pin_file")
current_rev=$(jq -er .rev "$pin_file")

if [[ $mode == release ]]; then
  if ! release=$(find_latest_release); then
    printf 'No normal Xen Orchestra release found in %s root changelog page(s)\n' "$release_scan_pages" >&2
    exit 1
  fi
  commit_sha=$(jq -er .sha <<<"$release")
  commit_subject=$(jq -er .subject <<<"$release")
  new_version=$(jq -er .version <<<"$release")
  printf 'Found normal XO release: %s\nVersion: %s\nCommit: %s\n' "$commit_subject" "$new_version" "$commit_sha"
else
  if [[ -n $upstream_rev ]]; then
    commit_sha=$upstream_rev
  else
    printf 'Resolving latest upstream source commit from %s %s...\n' "$upstream_remote" "$upstream_ref"
    commit_sha=$(retry 3 git ls-remote "$upstream_remote" "$upstream_ref" | awk 'NR == 1 { print $1 }')
  fi
  new_version=$current_version
  [[ $commit_sha =~ ^[a-f0-9]{40}$ ]] || { printf 'Failed to resolve upstream ref\n' >&2; exit 1; }
fi

if [[ $commit_sha == "$current_rev" && $new_version == "$current_version" ]]; then
  printf 'xen-orchestra-ce is already current at %s (%s)\n' "$current_version" "$current_rev"
  exit 0
fi
if [[ $mode == release ]]; then
  if [[ $new_version == "$current_version" ]]; then
    printf 'Refusing a second commit for existing XO version %s\n' "$current_version" >&2
    exit 1
  fi
  highest=$(printf '%s\n%s\n' "$current_version" "$new_version" | sort -V | tail -n 1)
  if [[ $highest != "$new_version" ]]; then
    printf 'Refusing to downgrade XO from %s to %s\n' "$current_version" "$new_version" >&2
    exit 1
  fi
fi

owner=$(jq -er .owner "$pin_file")
repo=$(jq -er .repo "$pin_file")
source_url="https://github.com/$owner/$repo/archive/$commit_sha.tar.gz"
prefetch=$(prefetch_source "$source_url")
new_hash=$(jq -er '.hash | select(startswith("sha256-"))' <<<"$prefetch")
if [[ -n ${XO_NIXPKG_PREFETCH_JSON:-} ]]; then
  new_source=$(jq -er '.storePath | select(type == "string")' <<<"$prefetch")
else
  new_source=$(jq -er '.storePath | select(startswith("/nix/store/"))' <<<"$prefetch")
fi
[[ -f $new_source/yarn.lock && -f $new_source/docs/yarn.lock ]] || {
  printf 'Prefetched XO source is missing a required Yarn lock\n' >&2
  exit 1
}

if [[ $mode == release ]]; then
  changelog_version=$(sed -nE 's/^## \*\*([0-9]+(\.[0-9]+)+)\*\*.*/\1/p' "$new_source/CHANGELOG.md" | head -n 1)
  if [[ $changelog_version != "$new_version" ]]; then
    printf 'Release marker %s does not match root changelog version %s\n' "$new_version" "${changelog_version:-missing}" >&2
    exit 1
  fi
fi

current_source=${XO_NIXPKG_CURRENT_SOURCE:-}
if [[ -z $current_source ]]; then
  current_source=$(nix build --accept-flake-config --no-link --print-out-paths '.#xen-orchestra-ce.src')
fi

new_yarn_hash=$(jq -er .yarnHash "$pin_file")
if ! cmp -s "$current_source/yarn.lock" "$new_source/yarn.lock"; then
  [[ -n ${XO_NIXPKG_NIXPKGS_PATH:-} ]] || { printf 'XO_NIXPKG_NIXPKGS_PATH is required\n' >&2; exit 1; }
  new_yarn_hash=$(retry 5 prefetch_yarn_hash "$new_source/yarn.lock" true)
fi
new_docs_yarn_hash=$(jq -er .docsYarnHash "$pin_file")
if ! cmp -s "$current_source/docs/yarn.lock" "$new_source/docs/yarn.lock"; then
  [[ -n ${XO_NIXPKG_NIXPKGS_PATH:-} ]] || { printf 'XO_NIXPKG_NIXPKGS_PATH is required\n' >&2; exit 1; }
  new_docs_yarn_hash=$(retry 5 prefetch_yarn_hash "$new_source/docs/yarn.lock" false)
fi

esbuild_version=$(lock_version "$new_source/yarn.lock" '@esbuild/linux-x64')
turbo_version=$(lock_version "$new_source/yarn.lock" '@turbo/linux-64')
rollup_version=$(lock_version "$new_source/yarn.lock" '@rollup/rollup-linux-x64-gnu')
[[ -n $turbo_version ]] || { printf 'Failed to find @turbo/linux-64 in upstream yarn.lock\n' >&2; exit 1; }

x86_esbuild=$(tool_json "$esbuild_version" "_esbuild_linux_x64___linux_x64_$esbuild_version.tgz" package/bin/esbuild)
x86_turbo=$(tool_json "$turbo_version" "_turbo_linux_64___linux_64_$turbo_version.tgz" turbo-linux-x64/bin/turbo)
x86_rollup=$(tool_json "$rollup_version" "_rollup_rollup_linux_x64_gnu___rollup_linux_x64_gnu_$rollup_version.tgz" package/rollup.linux-x64-gnu.node linux-x64-gnu)
arm_esbuild=$(tool_json "$esbuild_version" "_esbuild_linux_arm64___linux_arm64_$esbuild_version.tgz" package/bin/esbuild)
arm_turbo=$(tool_json "$turbo_version" "_turbo_linux_arm64___linux_arm64_$turbo_version.tgz" turbo-linux-arm64/bin/turbo)
arm_rollup=$(tool_json "$rollup_version" "_rollup_rollup_linux_arm64_gnu___rollup_linux_arm64_gnu_$rollup_version.tgz" package/rollup.linux-arm64-gnu.node linux-arm64-gnu)
platform_tools=$(jq -cn \
  --argjson x86Esbuild "$x86_esbuild" --argjson x86Turbo "$x86_turbo" --argjson x86Rollup "$x86_rollup" \
  --argjson armEsbuild "$arm_esbuild" --argjson armTurbo "$arm_turbo" --argjson armRollup "$arm_rollup" \
  '{"x86_64-linux":{esbuild:$x86Esbuild,turbo:$x86Turbo,rollup:$x86Rollup},"aarch64-linux":{esbuild:$armEsbuild,turbo:$armTurbo,rollup:$armRollup}}')

pin_directory=$(dirname "$pin_file")
temporary_pin=$(mktemp "$pin_directory/.xen-orchestra.json.XXXXXX")
trap 'rm -f "$temporary_pin"' EXIT
jq \
  --arg version "$new_version" --arg rev "$commit_sha" --arg hash "$new_hash" \
  --arg yarnHash "$new_yarn_hash" --arg docsYarnHash "$new_docs_yarn_hash" \
  --argjson platformTools "$platform_tools" '
    .version = $version |
    .rev = $rev |
    .hash = $hash |
    .yarnHash = $yarnHash |
    .docsYarnHash = $docsYarnHash |
    .platformTools = $platformTools
  ' "$pin_file" >"$temporary_pin"
jq -e '.schemaVersion == 1 and (.rev | test("^[a-f0-9]{40}$")) and (.platformTools["x86_64-linux"].turbo.version | length > 0)' "$temporary_pin" >/dev/null
mv "$temporary_pin" "$pin_file"
trap - EXIT

printf 'Updated XO source lock to %s (%s)\n' "$new_version" "$commit_sha"
printf '  source: %s\n  yarn: %s\n  docs yarn: %s\n' "$new_hash" "$new_yarn_hash" "$new_docs_yarn_hash"
