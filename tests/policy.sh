#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

[[ $(tr -d '\r\n' <"$root/VERSION") == 0.9.5 ]]
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
  .schemaVersion == 2 and
  .owner == "vatesfr" and
  .repo == "xen-orchestra" and
  (.channels | keys == ["latest", "rolling", "stable"]) and
  (.channels.latest.version | test("^[0-9]+(\\.[0-9]+)+$")) and
  (.channels.stable.version | test("^[0-9]+(\\.[0-9]+)+$")) and
  (.channels.rolling.version | test("^unstable-[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and
  all(.channels[]; (.rev | test("^[a-f0-9]{40}$"))) and
  all(.channels[]; has("platformTools") | not) and
  all(.channels[]; has("hash") | not)
' "$root/nix/sources/xen-orchestra.json" >/dev/null

for channel in latest stable rolling; do
  rev=$(jq -er ".channels.$channel.rev" "$root/nix/sources/xen-orchestra.json")
  rg -F "url = \"github:vatesfr/xen-orchestra/$rev\";" "$root/flake.nix" >/dev/null
  rg -F "$channel = mkXo \"$channel\"" "$root/flake.nix" >/dev/null
  rg -F "supply-protector-$channel" "$root/flake.nix" >/dev/null
done

rg -F 'exportReferencesGraph' "$root/nix/supply-protector.nix" >/dev/null
rg -F 'xen-orchestra.spdx.json' "$root/nix/supply-protector.sh" >/dev/null
rg -F 'xen-orchestra.cdx.json' "$root/nix/supply-protector.sh" >/dev/null

jq -e '
  .name == "Protect main with merge queue and CI gate" and
  .enforcement == "active" and
  ([.rules[].type] | index("deletion") != null) and
  ([.rules[].type] | index("non_fast_forward") != null) and
  any(.rules[]; .type == "merge_queue" and
    .parameters.merge_method == "MERGE" and
    .parameters.max_entries_to_merge == 1) and
  any(.rules[]; .type == "pull_request" and .parameters.required_review_thread_resolution == true) and
  any(.rules[]; .type == "required_status_checks" and
    .parameters.strict_required_status_checks_policy == false and
    any(.parameters.required_status_checks[]; .context == "CI gate"))
' "$root/.github/rulesets/main.json" >/dev/null

for application in \
  ci \
  publish \
  publish-release \
  tag-release \
  queue-automation \
  update-xo-release \
  update-xo-rolling \
  prewarm-rolling-candidate \
  update-libvhdi \
  open-update-pr \
  update-flake-lock; do
  rg -F "nix run .#$application" "$root/.github/workflows" >/dev/null
done

rg -F 'bash ci/classify.sh "$GITHUB_OUTPUT"' \
  "$root/.github/workflows/ci.yml" "$root/.github/workflows/publish.yml" >/dev/null

rg -F 'ciWorkflows = forAllSystems' "$root/flake.nix" >/dev/null
rg -F 'prepareCiWorkflow = prepare' "$root/nix/ci-workflow.nix" >/dev/null
rg -F 'evaluateCiWorkflowGate' "$root/nix/ci-workflow.nix" "$root/nix/ci-gate-runtime.nix" >/dev/null
rg -F 'PREPARED_CI_WORKFLOW' "$root/ci/run.sh" "$root/ci/publish.sh" "$root/nix/ci-gate-runtime.nix" >/dev/null
rg -F 'flake-plan-runner' "$root/ci/run.sh" >/dev/null
rg -F -- '--plan-file' "$root/ci/run.sh" "$root/ci/publish.sh" >/dev/null
rg -F 'schemaVersion = 2' "$root/nix/ci-plan.nix" >/dev/null

for removed_wrapper in \
  ci/prepare.sh \
  ci/gate.sh \
  ci/update-xo-release.sh \
  ci/update-xo-upstream.sh \
  ci/maintain-latest-upstream.sh \
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
if rg -F -e 'UPDATE_GITHUB_APP_' -e 'create-github-app-token' "$root/.github"; then
  echo 'GitHub automation must use the scoped built-in token' >&2
  exit 1
fi
rg -F 'UPDATE_AUTHOR: github-actions' "$root/.github/workflows/queue-automation.yml" >/dev/null
if rg -F 'UPDATE_AUTHOR: github-actions[bot]' "$root/.github/workflows/queue-automation.yml"; then
  echo 'Trusted automation must compare the normalized GitHub Actions login' >&2
  exit 1
fi
rg -F 'actions/runs/${run_id}/approve' "$root/ci/trusted-update.sh" >/dev/null
if rg -F 'gh workflow run "$ci_workflow"' "$root/ci/trusted-update.sh"; then
  echo 'Trusted automation must approve native pull-request CI instead of dispatching detached CI' >&2
  exit 1
fi

if rg 'run:.*(\./ci/|\./scripts/)' "$root/.github/workflows"; then
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
  "$root"/.github/workflows/*.yml | grep -v '^---$')

yq -e '
  [.jobs[].steps[] | select(.uses == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1") |
    .with."persist-credentials"] | all_c(. == false)
' "$root"/.github/workflows/*.yml >/dev/null

# actionlint 1.7.12 predates GitHub's queue:max concurrency extension.
actionlint -ignore 'unexpected key "queue"' "$root"/.github/workflows/*.yml
zizmor "$root/.github"
shellcheck "$root"/ci/*.sh "$root"/scripts/*.sh "$root"/tests/*.sh

printf 'Repository policy passed\n'
