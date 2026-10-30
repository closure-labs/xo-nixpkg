#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
jq -e '.schema == 1 and (.enabled | type == "boolean") and (if .enabled then .appId > 0 else true end) and .repository == "closure-labs/xo-nixpkg" and .profiles == ["xo-latest","xo-stable","xo-rolling","libvhdi"]' ci/decision-policy.json >/dev/null
jq -e '.schemaVersion == 2 and (.channels | keys == ["latest","rolling","stable"])' nix/sources/xen-orchestra.json >/dev/null
for channel in latest stable rolling; do
  rev=$(jq -er ".channels.$channel.rev" nix/sources/xen-orchestra.json)
  rg -F "url = \"github:vatesfr/xen-orchestra/$rev\";" flake.nix >/dev/null
done
if rg -e 'CACHIX_AUTH_TOKEN|cachix push' ci/prewarm-rolling.sh ci/prewarm-candidate.sh .github/workflows/update-rolling.yml .github/workflows/update-check.yml .github/workflows/prewarm-runtime.yml; then
  echo 'Rolling candidate realization must not distribute packages' >&2
  exit 1
fi
for leaf in publish tag-release tag-xo-release publish-release; do
  rg -F 'xo-nixpkg-publication-gate' "ci/$leaf.sh" >/dev/null
done
if rg 'run:.*(\./ci/|\./scripts/|nix run \.#(ci|publish|update-|tag-))' .github/workflows; then
  echo 'Workflow policy must execute through declared devenv tasks' >&2
  exit 1
fi
while IFS= read -r action; do
  [[ $action == ./* ]] || [[ $action =~ @[0-9a-f]{40}$ ]] || {
    printf 'Unpinned action: %s\n' "$action" >&2
    exit 1
  }
done < <(yq -r '.. | .uses? | select(. != null)' .github/actions/*/*.yml .github/workflows/*.yml | sed '/^---$/d')
rg -F 'ref: main' .github/workflows/publish.yml .github/workflows/decision-authority.yml >/dev/null
yq -e '.jobs.publish.environment == "publication" and .concurrency.queue == "max" and .concurrency.cancel-in-progress == false' .github/workflows/publish.yml >/dev/null
rg -F "if: github.repository == 'closure-labs/xo-nixpkg' && github.ref == 'refs/heads/main'" .github/workflows/publish.yml .github/workflows/security-reconcile.yml >/dev/null
rg -F 'permission-checks: write' .github/workflows/decision-authority.yml >/dev/null
rg -F 'export XO_NIXPKG_PUBLICATION_PURPOSE=release' ci/tag-release.sh ci/tag-xo-release.sh ci/publish-release.sh >/dev/null
if rg 'persist-credentials: true|cachix\.push|git tag -f' .github devenv.nix ci; then
  echo 'Credential persistence or mutable publication is forbidden' >&2
  exit 1
fi
if [[ ${XO_NIXPKG_SHARED_FIXTURES_READY:-false} != true ]]; then
  bash ci/security-fixtures.sh
fi
shellcheck ci/*.sh scripts/*.sh tests/*.sh
bash tests/publication-boundary.sh
printf 'Repository policy passed\n'
