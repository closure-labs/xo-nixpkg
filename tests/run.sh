#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

jq -e '
  .pins.libvhdi as $pin |
  .version == 8 and
  $pin.type == "Url" and
  $pin.unpack == true and
  ($pin.version | test("^[0-9]{8}$")) and
  ($pin.url | endswith("/libvhdi-alpha-" + $pin.version + ".tar.gz"))
' "$root/npins/sources.json" >/dev/null

jq -e '
  .name == "Protect main with an up-to-date CI gate" and
  .enforcement == "active" and
  ([.rules[].type] | index("deletion") != null) and
  ([.rules[].type] | index("non_fast_forward") != null) and
  any(.rules[]; .type == "pull_request" and .parameters.required_review_thread_resolution == true) and
  any(.rules[]; .type == "required_status_checks" and
    .parameters.strict_required_status_checks_policy == true and
    any(.parameters.required_status_checks[]; .context == "CI gate"))
' "$root/.github/rulesets/main.json" >/dev/null

bash "$root/tests/update-libvhdi.sh"
bash "$root/tests/trusted-update.sh"
bash "$root/tests/tag-release.sh"
bash "$root/tests/flake-attribute-validator.sh"

for application in \
  ci \
  publish \
  tag-release \
  queue-automation \
  update-xo-release \
  update-libvhdi \
  maintain-latest-upstream \
  forgejo-update; do
  rg -F "nix run .#$application" "$root/.github/workflows" "$root/.forgejo/workflows" >/dev/null
done

rg -F 'lib.ciPlans.${pkgs.stdenv.hostPlatform.system}.validation' \
  "$root/nix/applications.nix" >/dev/null
rg -F 'flake-attribute-validator' "$root/ci/run.sh" >/dev/null

if rg 'run:.*(\./ci/|\./scripts/)' "$root/.github/workflows" "$root/.forgejo/workflows"; then
  echo 'Workflows must invoke repository automation through flake apps' >&2
  exit 1
fi

while IFS= read -r action; do
  [[ $action == ./* ]] || [[ $action =~ @[0-9a-f]{40}$ ]] || {
    echo "Unpinned workflow action: $action" >&2
    exit 1
  }
done < <(sed -nE 's/^[[:space:]]*uses:[[:space:]]*([^[:space:]#]+).*/\1/p' \
  "$root"/.github/actions/*/*.yml \
  "$root"/.github/workflows/*.yml \
  "$root"/.forgejo/workflows/*.yml)

printf 'Repository fixtures passed\n'
