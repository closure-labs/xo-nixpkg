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

usage() {
    cat <<EOF
Usage: $0 [--release|--upstream]

Modes:
  --release   Update to the latest "feat: release X.Y.Z" commit. This is the default.
  --upstream  Update src.rev and hashes to the latest upstream source commit.
EOF
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
    exec nix develop "$repo_root" --command bash "$script_dir/update.sh" "--$mode"
fi

cd "$repo_root"

current_version=$(sed -n 's/.*version = "\([^"]*\)".*/\1/p' default.nix | head -n 1)

if [ -z "$current_version" ]; then
    echo "Failed to extract current version from default.nix" >&2
    exit 1
fi

if [ "$mode" = "release" ]; then
    echo "Searching for latest version commit in xen-orchestra..."

    # Get recent commits and find the latest version bump.
    version_info=$(curl -fsSL "https://api.github.com/repos/vatesfr/xen-orchestra/commits?per_page=100" | \
        jq -r '.[] | select((.commit.message | split("\n")[0]) | test("^feat: release [0-9]+(\\.[0-9]+)+")) | {sha: .sha, message: .commit.message} | @json' | \
        head -1)

    if [ -z "$version_info" ] || [ "$version_info" = "null" ]; then
        echo "No version commit found in recent history" >&2
        exit 1
    fi

    commit_sha=$(echo "$version_info" | jq -r '.sha')
    commit_msg=$(echo "$version_info" | jq -r '.message')
    commit_subject=$(printf '%s\n' "$commit_msg" | sed -n '1p')
    new_version=$(printf '%s\n' "$commit_subject" | sed -nE 's/^feat: release ([0-9]+(\.[0-9]+)+).*/\1/p')

    if [ -z "$new_version" ]; then
        echo "Failed to extract version from commit message: $commit_subject" >&2
        exit 1
    fi

    echo "Found: $commit_msg"
    echo "Version: $new_version"
    echo "Commit: $commit_sha"
else
    echo "Resolving latest upstream source commit from $upstream_remote $upstream_ref..."

    commit_sha=$(git ls-remote "$upstream_remote" "$upstream_ref" | awk 'NR == 1 { print $1 }')
    new_version="$current_version"

    if [ -z "$commit_sha" ]; then
        echo "Failed to resolve upstream ref: $upstream_ref" >&2
        exit 1
    fi

    echo "Version: $new_version (unchanged)"
    echo "Commit: $commit_sha"
fi

# Get the new source hash
echo "Fetching source hash..."
new_hash=$(nix-prefetch-github vatesfr xen-orchestra --rev "$commit_sha" | jq -r '.hash')

echo "New source hash: $new_hash"

# Get yarnOfflineCache hash from the new yarn.lock
echo "Fetching yarnOfflineCache hash..."
placeholder_hash="sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
nixpkgs_path=$(nix eval --raw --impure --expr "(builtins.getFlake \"path:$repo_root\").inputs.nixpkgs.outPath")
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

set +e
yarn_prefetch_output=$(nix-build --no-out-link -E "$prefetch_expr" 2>&1)
yarn_prefetch_status=$?
set -e

if [ "$yarn_prefetch_status" -eq 0 ]; then
    echo "Unexpectedly resolved yarnOfflineCache with placeholder hash" >&2
    exit 1
fi

new_yarn_hash=$(printf '%s\n' "$yarn_prefetch_output" | \
    sed -n 's/^[[:space:]]*got:[[:space:]]*\(sha256-[A-Za-z0-9+/=]*\).*/\1/p' | \
    head -1)

if [ -z "$new_yarn_hash" ]; then
    echo "Failed to extract yarnOfflineCache hash from nix-build output" >&2
    echo "$yarn_prefetch_output" >&2
    exit 1
fi

echo "New yarn hash: $new_yarn_hash"

# Update default.nix
if [ "$mode" = "release" ]; then
    sed -i "s/version = \"[^\"]*\"/version = \"$new_version\"/" default.nix
fi
sed -i "s/rev = \"[a-f0-9]*\"/rev = \"$commit_sha\"/" default.nix
sed -i "/src = fetchFromGitHub {/,/};/ s|hash = \"[^\"]*\"|hash = \"$new_hash\"|" default.nix
sed -i "/yarnOfflineCache = /,/};/ s|hash = \"[^\"]*\"|hash = \"$new_yarn_hash\"|" default.nix

echo ""
if [ "$mode" = "release" ]; then
    echo "Updated default.nix to version $new_version"
else
    echo "Updated default.nix to upstream source commit $commit_sha"
    echo "  version: $new_version (unchanged)"
fi
echo "  src.hash: $new_hash"
echo "  yarnOfflineCache.hash: $new_yarn_hash"
