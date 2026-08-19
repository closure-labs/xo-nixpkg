#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${FORGEJO_TOKEN:?FORGEJO_TOKEN must be set}"
mode=${1:?usage: forgejo-update.sh xo|libvhdi}
case "$mode" in
  xo)
    xo-nixpkg-update-xo-release
    changed_paths=(nix/sources/xen-orchestra.json)
    version=$(nix eval --accept-flake-config --raw .#xen-orchestra-ce.version)
    rev=$(nix eval --accept-flake-config --raw .#xen-orchestra-ce.src.rev)
    branch="update/xen-orchestra-ce-$version"
    title="xen-orchestra-ce: update to $version"
    body="Automated update to vatesfr/xen-orchestra@$rev. Validated with nix run .#update-xo-release."
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
git switch -c "$branch"
git add "${changed_paths[@]}"
git commit -m "$title"
git remote set-url origin "https://oauth2:${FORGEJO_TOKEN}@codeberg.org/NiXOA/xen-orchestra-ce.git"
git push origin "$branch"

jq -n \
  --arg base main \
  --arg body "$body" \
  --arg head "$branch" \
  --arg title "$title" \
  '{base:$base,body:$body,head:$head,title:$title}' |
  curl --fail-with-body \
    --header "Authorization: token $FORGEJO_TOKEN" \
    --header 'Content-Type: application/json' \
    --data-binary @- \
    https://codeberg.org/api/v1/repos/NiXOA/xen-orchestra-ce/pulls
