#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

[[ $(tr -d '\r\n' <"$root/VERSION") == 0.8.0 ]]
rg -F 'version=$(tr -d' "$root/ci/tag-release.sh" >/dev/null
if rg -F '.#xen-orchestra-ce.version' "$root/ci/tag-release.sh"; then
  echo 'Project tags must use the repository version' >&2
  exit 1
fi

jq -e '
  .schemaVersion == 1 and
  .type == "Url" and
  .unpack == true and
  (.version | test("^[0-9]{8}$")) and
  (. as $pin | .url | endswith("/libvhdi-alpha-" + $pin.version + ".tar.gz"))
' "$root/nix/sources/libvhdi.json" >/dev/null

jq -e '
  .schemaVersion == 1 and
  .owner == "vatesfr" and
  .repo == "xen-orchestra" and
  (.version | test("^[0-9]+(\\.[0-9]+)+$")) and
  (.rev | test("^[a-f0-9]{40}$")) and
  (.platformTools["x86_64-linux"].turbo.version | length > 0)
' "$root/nix/sources/xen-orchestra.json" >/dev/null

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

for application in \
  prepare-ci \
  ci \
  ci-gate \
  publish \
  publish-release \
  tag-release \
  queue-automation \
  update-xo-release \
  update-libvhdi \
  open-update-pr \
  update-flake-lock \
  maintain-latest-upstream \
  forgejo-update; do
  rg -F "nix run .#$application" "$root/.github/workflows" "$root/.forgejo/workflows" >/dev/null
done

rg -F 'ciWorkflows = forAllSystems' "$root/flake.nix" >/dev/null
rg -F 'prepareCiWorkflow = prepare' "$root/nix/ci-workflow.nix" >/dev/null
rg -F 'evaluateCiWorkflowGate' "$root/nix/ci-workflow.nix" "$root/nix/ci-gate-runtime.nix" >/dev/null
rg -F 'PREPARED_CI_WORKFLOW' "$root/ci/run.sh" "$root/ci/publish.sh" "$root/nix/ci-gate-runtime.nix" >/dev/null
rg -F 'flake-plan-runner' "$root/ci/run.sh" >/dev/null
rg -F 'schemaVersion = 2' "$root/nix/ci-plan.nix" >/dev/null

for removed_wrapper in \
  ci/prepare.sh \
  ci/gate.sh \
  ci/update-xo-release.sh \
  ci/update-xo-upstream.sh \
  tests/run.sh; do
  [[ ! -e $root/$removed_wrapper ]] || {
    echo "Obsolete shell wrapper still exists: $removed_wrapper" >&2
    exit 1
  }
done

if rg -F 'magic-nix-cache-action' "$root/.github"; then
  echo 'GitHub workflows must not use Magic Nix Cache' >&2
  exit 1
fi
if rg -F 'peter-evans/create-pull-request' "$root/.github"; then
  echo 'Source updates must use flake-packaged pull-request automation' >&2
  exit 1
fi
if rg -F 'DeterminateSystems/update-flake-lock' "$root/.github"; then
  echo 'Lock updates must use flake-packaged automation' >&2
  exit 1
fi
if rg -F 'UPDATE_GITHUB_APP_ID' "$root/.github"; then
  echo 'GitHub App automation must use the client ID' >&2
  exit 1
fi

if rg 'run:.*(\./ci/|\./scripts/)' "$root/.github/workflows" "$root/.forgejo/workflows"; then
  echo 'Workflows must invoke repository automation through flake apps' >&2
  exit 1
fi

while IFS= read -r action; do
  [[ $action == ./* ]] || [[ $action =~ @[0-9a-f]{40}$ ]] || {
    echo "Unpinned workflow action: $action" >&2
    exit 1
  }
done < <(yq -r '.. | .uses? | select(. != null)' \
  "$root"/.github/actions/*/*.yml \
  "$root"/.github/workflows/*.yml \
  "$root"/.forgejo/workflows/*.yml | grep -v '^---$')

yq -e '
  [.jobs[].steps[] | select(.uses == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1") |
    .with."persist-credentials"] | all_c(. == false)
' "$root"/.github/workflows/*.yml >/dev/null

actionlint "$root"/.github/workflows/*.yml
zizmor "$root/.github"
shellcheck "$root"/ci/*.sh "$root"/scripts/*.sh "$root"/tests/*.sh

printf 'Repository policy passed\n'
