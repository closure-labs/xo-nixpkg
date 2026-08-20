#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${FORGEJO_TOKEN:?FORGEJO_TOKEN must be set}"
mode=${1:?usage: forgejo-update.sh xo|libvhdi}
case "$mode" in
  xo)
    xo-nixpkg-update-xo-release
    changed_paths=(flake.nix flake.lock nix/sources/xen-orchestra.json)
    version=$(jq -er .channels.latest.version nix/sources/xen-orchestra.json)
    rev=$(jq -er .channels.latest.rev nix/sources/xen-orchestra.json)
    branch="automation/xo-release-channels"
    title="xen-orchestra-ce channels: refresh official releases"
    body="Automated latest/stable channel refresh to Xen Orchestra $version at $rev."
    ;;
  libvhdi)
    xo-nixpkg-update-libvhdi
    changed_paths=(nix/sources/libvhdi.json)
    version=$(jq -er .version nix/sources/libvhdi.json)
    branch="update/libvhdi-$version"
    title="libvhdi: update to $version"
    body='Automated source-lock refresh to the official libvhdi release asset. Validated with nix run .#update-libvhdi.'
    ;;
  *)
    echo "Unsupported update mode: $mode" >&2
    exit 2
    ;;
esac

if git diff --quiet -- "${changed_paths[@]}"; then
  exit 0
fi

git config user.name 'Forgejo Actions'
git config user.email 'actions@codeberg.org'
git remote set-url origin "https://oauth2:${FORGEJO_TOKEN}@codeberg.org/NiXOA/xen-orchestra-ce.git"
remote_sha=$(git ls-remote --refs origin "refs/heads/$branch" | cut -f1)
if [[ -n $remote_sha ]] && git diff --quiet "$remote_sha" -- "${changed_paths[@]}"; then
  echo 'The candidate is already published on the update branch'
  exit 0
fi
git switch -C "$branch"
git add "${changed_paths[@]}"
git commit -m "$title"
git push --force-with-lease="refs/heads/$branch:$remote_sha" origin "$branch"

api=https://codeberg.org/api/v1/repos/NiXOA/xen-orchestra-ce
open_pr=$(curl --fail-with-body --silent --show-error \
  --header "Authorization: token $FORGEJO_TOKEN" \
  "$api/pulls?state=open" |
  jq -r --arg branch "$branch" '[.[] | select(.head.ref == $branch)][0].number // empty')
payload=$(jq -cn \
  --arg base main --arg body "$body" --arg head "$branch" --arg title "$title" \
  '{base:$base,body:$body,head:$head,title:$title}')
if [[ -n $open_pr ]]; then
  curl --fail-with-body \
    --header "Authorization: token $FORGEJO_TOKEN" \
    --header 'Content-Type: application/json' \
    --request PATCH --data-binary "$payload" "$api/pulls/$open_pr"
else
  curl --fail-with-body \
    --header "Authorization: token $FORGEJO_TOKEN" \
    --header 'Content-Type: application/json' \
    --data-binary "$payload" "$api/pulls"
fi
