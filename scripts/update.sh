#!/usr/bin/env bash

set -euo pipefail

# Xen Orchestra doesn't use git tags. Versions are indicated in commit messages
# like "feat: release 6.3.3". This script searches recent commits for version
# bumps based on the first line of the commit message.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

if [ -z "${XO_NIXPKG_UPDATE_IN_DEV_SHELL:-}" ]; then
    export XO_NIXPKG_UPDATE_IN_DEV_SHELL=1
    exec nix develop "$repo_root" --command bash "$script_dir/update.sh" "$@"
fi

cd "$repo_root"

echo "Searching for latest version commit in xen-orchestra..."

# Get recent commits and find the latest version bump
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
sed -i "s/version = \"[^\"]*\"/version = \"$new_version\"/" default.nix
sed -i "s/rev = \"[a-f0-9]*\"/rev = \"$commit_sha\"/" default.nix
sed -i "/src = fetchFromGitHub {/,/};/ s|hash = \"[^\"]*\"|hash = \"$new_hash\"|" default.nix
sed -i "/yarnOfflineCache = /,/};/ s|hash = \"[^\"]*\"|hash = \"$new_yarn_hash\"|" default.nix

echo ""
echo "Updated default.nix to version $new_version"
echo "  src.hash: $new_hash"
echo "  yarnOfflineCache.hash: $new_yarn_hash"
