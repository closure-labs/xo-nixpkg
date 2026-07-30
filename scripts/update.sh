#!/usr/bin/env bash

set -euo pipefail

# Xen Orchestra doesn't use git tags. Versions are indicated in commit messages
# like "feat: release 6.3.3". By default this script searches recent commits for
# version bumps based on the first line of the commit message.
#
# Use --upstream to track the latest upstream source commit without changing the
# packaged version. This is intended for the latest-upstream tag workflow.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

mode="release"
upstream_remote="${XO_NIXPKG_UPSTREAM_REMOTE:-https://github.com/vatesfr/xen-orchestra.git}"
upstream_ref="${XO_NIXPKG_UPSTREAM_REF:-refs/heads/master}"
release_scan_pages="${XO_NIXPKG_RELEASE_SCAN_PAGES:-20}"

usage() {
    cat <<EOF
Usage: $0 [--release|--upstream]

Modes:
  --release   Update to the latest "feat: release X.Y.Z" commit. This is the default.
  --upstream  Update src.rev and hashes to the latest upstream source commit.
EOF
}

retry() {
    local max_attempts="$1"
    shift

    local attempt
    for attempt in $(seq 1 "$max_attempts"); do
        if "$@"; then
            return 0
        fi

        if [ "$attempt" -eq "$max_attempts" ]; then
            echo "Command failed after $attempt attempts: $*" >&2
            return 1
        fi

        echo "Retrying after transient failure (attempt $attempt failed): $*" >&2
        sleep $((attempt * 15))
    done
}

github_api() {
    local url="$1"

    if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl -fsSL \
            -H "Authorization: Bearer $GITHUB_TOKEN" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "$url"
    else
        curl -fsSL "$url"
    fi
}

find_latest_release() {
    local page
    local response
    local commit_count
    local version_info

    for page in $(seq 1 "$release_scan_pages"); do
        echo "Scanning upstream commits page $page for release marker..." >&2

        response=$(retry 3 github_api "https://api.github.com/repos/vatesfr/xen-orchestra/commits?per_page=100&page=$page")
        commit_count=$(printf '%s\n' "$response" | jq 'length')

        if [ "$commit_count" -eq 0 ]; then
            break
        fi

        version_info=$(printf '%s\n' "$response" | jq -r '
          (
            [
              .[]
              | .commit.message as $message
              | ($message | split("\n")[0]) as $subject
              | ($subject | capture("^feat: release (?<version>[0-9]+(\\.[0-9]+)+)([[:space:]].*)?$")?) as $release
              | select($release != null)
              | {sha: .sha, subject: $subject, version: $release.version}
            ][0] // empty
          )
          | @json
        ')

        if [ -n "$version_info" ] && [ "$version_info" != "null" ]; then
            printf '%s\n' "$version_info"
            return 0
        fi
    done

    return 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --release)
            mode="release"
            ;;
        --upstream)
            mode="upstream"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [ -z "${XO_NIXPKG_UPDATE_IN_DEV_SHELL:-}" ]; then
    export XO_NIXPKG_UPDATE_IN_DEV_SHELL=1
    exec nix develop --accept-flake-config "$repo_root#updater" --command bash "$script_dir/update.sh" "--$mode"
fi

cd "$repo_root"

current_version=$(nix eval --accept-flake-config --raw .#packages.x86_64-linux.xen-orchestra-ce.version)
current_rev=$(nix eval --accept-flake-config --raw .#packages.x86_64-linux.xen-orchestra-ce.src.rev)

if [ -z "$current_version" ]; then
    echo "Failed to evaluate current xen-orchestra-ce version" >&2
    exit 1
fi

if [ -z "$current_rev" ]; then
    echo "Failed to evaluate current xen-orchestra-ce source revision" >&2
    exit 1
fi

if [ "$mode" = "release" ]; then
    echo "Searching for latest version commit in xen-orchestra..."

    if ! version_info=$(find_latest_release); then
        echo "No version commit found in the first $release_scan_pages pages of upstream history" >&2
        exit 1
    fi

    commit_sha=$(echo "$version_info" | jq -r '.sha')
    commit_subject=$(echo "$version_info" | jq -r '.subject')
    new_version=$(echo "$version_info" | jq -r '.version')

    if [ -z "$new_version" ]; then
        echo "Failed to extract version from commit message: $commit_subject" >&2
        exit 1
    fi

    echo "Found: $commit_subject"
    echo "Version: $new_version"
    echo "Commit: $commit_sha"
else
    echo "Resolving latest upstream source commit from $upstream_remote $upstream_ref..."

    commit_sha=$(retry 3 git ls-remote "$upstream_remote" "$upstream_ref" | awk 'NR == 1 { print $1 }')
    new_version="$current_version"

    if [ -z "$commit_sha" ]; then
        echo "Failed to resolve upstream ref: $upstream_ref" >&2
        exit 1
    fi

    echo "Version: $new_version (unchanged)"
    echo "Commit: $commit_sha"
fi

if [ "$mode" = "release" ] && [ "$new_version" = "$current_version" ] && [ "$commit_sha" = "$current_rev" ]; then
    echo "xen-orchestra-ce is already at release $new_version ($commit_sha); no update needed."
    exit 0
fi

if [ "$mode" = "upstream" ] && [ "$commit_sha" = "$current_rev" ]; then
    echo "xen-orchestra-ce already tracks upstream source commit $commit_sha; no update needed."
    exit 0
fi

# Get the new source hash
echo "Fetching source hash..."
new_hash=$(retry 3 nix-prefetch-github vatesfr xen-orchestra --rev "$commit_sha" | jq -r '.hash')

echo "New source hash: $new_hash"

yarn_lock_file=$(mktemp)
trap 'rm -f "$yarn_lock_file"' EXIT
retry 3 curl -fsSL "https://raw.githubusercontent.com/vatesfr/xen-orchestra/$commit_sha/yarn.lock" -o "$yarn_lock_file"

lock_version() {
    local package="$1"

    awk -v package="$package" '
      index($0, "\"" package "@") == 1 { inEntry = 1; next }
      inEntry && $1 == "version" {
        gsub(/"/, "", $2)
        print $2
        exit
      }
      inEntry && /^$/ { inEntry = 0 }
    ' "$yarn_lock_file"
}

tool_attr() {
    local version="$1"
    local tarball="$2"
    local path="$3"
    local package_base="${4:-}"

    if [ -z "$version" ]; then
        printf 'null'
        return
    fi

    cat <<EOF
{
      version = "$version";
      tarball = "$tarball";
      path = "$path";
$(if [ -n "$package_base" ]; then printf '      packageBase = "%s";\n' "$package_base"; fi)    }
EOF
}

write_platform_tools_file() {
    local esbuild_version="$1"
    local turbo_version="$2"
    local rollup_version="$3"

    if [ -z "$turbo_version" ]; then
        echo "Failed to find @turbo/linux-64 in upstream yarn.lock" >&2
        exit 1
    fi

    cat > nix/platform-tools.nix <<EOF
{
  x86_64-linux = {
    esbuild = $(tool_attr "$esbuild_version" "_esbuild_linux_x64___linux_x64_$esbuild_version.tgz" "package/bin/esbuild");
    turbo = $(tool_attr "$turbo_version" "_turbo_linux_64___linux_64_$turbo_version.tgz" "turbo-linux-x64/bin/turbo");
    rollup = $(tool_attr "$rollup_version" "_rollup_rollup_linux_x64_gnu___rollup_linux_x64_gnu_$rollup_version.tgz" "package/rollup.linux-x64-gnu.node" "linux-x64-gnu");
  };
  aarch64-linux = {
    esbuild = $(tool_attr "$esbuild_version" "_esbuild_linux_arm64___linux_arm64_$esbuild_version.tgz" "package/bin/esbuild");
    turbo = $(tool_attr "$turbo_version" "_turbo_linux_arm64___linux_arm64_$turbo_version.tgz" "turbo-linux-arm64/bin/turbo");
    rollup = $(tool_attr "$rollup_version" "_rollup_rollup_linux_arm64_gnu___rollup_linux_arm64_gnu_$rollup_version.tgz" "package/rollup.linux-arm64-gnu.node" "linux-arm64-gnu");
  };
}
EOF
}

# Get yarnOfflineCache hash from the new yarn.lock
echo "Fetching yarnOfflineCache hash..."
placeholder_hash="sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
if [ -z "${XO_NIXPKG_NIXPKGS_PATH:-}" ]; then
    echo "XO_NIXPKG_NIXPKGS_PATH is not set; run this script through the .#updater shell" >&2
    exit 1
fi
nixpkgs_path="$XO_NIXPKG_NIXPKGS_PATH"
prefetch_expr=$(cat <<EOF
let
  pkgs = import $nixpkgs_path {};
  fetchNormalizedYarnDeps = import ./nix/fetch-normalized-yarn-deps.nix {
    inherit (pkgs) fetchYarnDeps;
  };
  src = pkgs.fetchFromGitHub {
    owner = "vatesfr";
    repo = "xen-orchestra";
    rev = "$commit_sha";
    hash = "$new_hash";
  };
in
fetchNormalizedYarnDeps {
  yarnLock = src + "/yarn.lock";
  hash = "$placeholder_hash";
}
EOF
)

docs_prefetch_expr=$(cat <<EOF
let
  pkgs = import $nixpkgs_path {};
  src = pkgs.fetchFromGitHub {
    owner = "vatesfr";
    repo = "xen-orchestra";
    rev = "$commit_sha";
    hash = "$new_hash";
  };
in
pkgs.fetchYarnDeps {
  yarnLock = src + "/docs/yarn.lock";
  hash = "$placeholder_hash";
}
EOF
)

prefetch_yarn_hash() {
    local expression="$1"
    local yarn_prefetch_output
    local yarn_prefetch_status
    local yarn_hash

    set +e
    yarn_prefetch_output=$(nix-build --no-out-link -E "$expression" 2>&1)
    yarn_prefetch_status=$?
    set -e

    if [ "$yarn_prefetch_status" -eq 0 ]; then
        echo "Unexpectedly resolved yarnOfflineCache with placeholder hash" >&2
        return 1
    fi

    yarn_hash=$(printf '%s\n' "$yarn_prefetch_output" | \
        sed -n 's/^[[:space:]]*got:[[:space:]]*\(sha256-[A-Za-z0-9+/=]*\).*/\1/p' | \
        head -n 1)

    if [ -n "$yarn_hash" ]; then
        printf '%s\n' "$yarn_hash"
        return 0
    fi

    echo "Failed to extract yarnOfflineCache hash from nix-build output" >&2
    printf '%s\n' "$yarn_prefetch_output" | tail -n 80 >&2
    return 1
}

new_yarn_hash=$(retry 5 prefetch_yarn_hash "$prefetch_expr")
new_docs_yarn_hash=$(retry 5 prefetch_yarn_hash "$docs_prefetch_expr")

echo "New yarn hash: $new_yarn_hash"
echo "New docs yarn hash: $new_docs_yarn_hash"

# Update default.nix
if [ "$mode" = "release" ]; then
    sed -i "/pname = \"xen-orchestra-ce\";/,/src = fetchFromGitHub {/ s|^\([[:space:]]*version = \"\)[^\"]*\(\";\)$|\1$new_version\2|" default.nix
fi
sed -i "/src = fetchFromGitHub {/,/};/ s|^\([[:space:]]*rev = \"\)[a-f0-9]*\(\";\)$|\1$commit_sha\2|" default.nix
sed -i "/src = fetchFromGitHub {/,/};/ s|hash = \"[^\"]*\"|hash = \"$new_hash\"|" default.nix
sed -i "/yarnOfflineCache = /,/};/ s|hash = \"[^\"]*\"|hash = \"$new_yarn_hash\"|" default.nix
sed -i "/docsYarnOfflineCache = /,/};/ s|hash = \"[^\"]*\"|hash = \"$new_docs_yarn_hash\"|" default.nix

esbuild_version=$(lock_version "@esbuild/linux-x64")
turbo_version=$(lock_version "@turbo/linux-64")
rollup_version=$(lock_version "@rollup/rollup-linux-x64-gnu")
write_platform_tools_file "$esbuild_version" "$turbo_version" "$rollup_version"

echo ""
if [ "$mode" = "release" ]; then
    echo "Updated default.nix to version $new_version"
else
    echo "Updated default.nix to upstream source commit $commit_sha"
    echo "  version: $new_version (unchanged)"
fi
echo "  src.hash: $new_hash"
echo "  yarnOfflineCache.hash: $new_yarn_hash"
echo "  docsYarnOfflineCache.hash: $new_docs_yarn_hash"
echo "  esbuild: ${esbuild_version:-not present in yarn.lock}"
echo "  turbo: $turbo_version"
echo "  rollup: ${rollup_version:-not present in yarn.lock}"
