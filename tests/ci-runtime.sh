#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary_directory=$(mktemp -d)
trap 'rm -rf -- "$temporary_directory"' EXIT
mkdir -p "$temporary_directory/bin"

prepared_pull_request=$(jq -cn '{
  schemaVersion: 1,
  name: "fixture-ci",
  system: "x86_64-linux",
  source: {attribute: "lib.ciWorkflows.x86_64-linux"},
  event: {name: "pull_request", ref: "refs/pull/14/merge"},
  jobs: {
    validate: {
      gate: true,
      plan: "lib.ciPlans.x86_64-linux.validation",
      enabled: true
    },
    publish: {
      gate: true,
      plan: "lib.ciPlans.x86_64-linux.publish",
      when: {event: "push", ref: "refs/heads/main"},
      enabled: false
    }
  },
  release: {
    when: {event: "push", ref: "refs/heads/main"},
    enabled: false
  },
  gate: {requiredJobs: ["validate"]}
}')
prepared_lifecycle=$(jq -cn '{
  schemaVersion: 2,
  event: {name: "pull_request", ref: "refs/pull/14/merge", headSha: "fixture"},
  classification: {mode: "full", reason: "fixture", changedPathCount: 0},
  jobs: {
    validate: {
      enabled: true,
      plan: {
        schemaVersion: 2,
        name: "fixture-validation",
        targets: [{name: "repository", attribute: "checks.x86_64-linux.repository"}]
      }
    },
    publish: {
      enabled: true,
      plan: {
        schemaVersion: 2,
        name: "fixture-publication",
        targets: [
          {name: "xen-orchestra-ce", attribute: "packages.x86_64-linux.xen-orchestra-ce"},
          {name: "libvhdi", attribute: "packages.x86_64-linux.libvhdi"}
        ]
      }
    }
  },
  release: {enabled: false}
}')

printf '#!%s\n' "$BASH" >"$temporary_directory/bin/runtime-nix"
cat >>"$temporary_directory/bin/runtime-nix" <<'EOF'
set -euo pipefail
printf '%s\n' "$FAKE_PREPARED_CI_WORKFLOW"
EOF
chmod +x "$temporary_directory/bin/runtime-nix"

output_file="$temporary_directory/github-output"
XO_NIXPKG_RUNTIME_NIX="$temporary_directory/bin/runtime-nix" \
FAKE_PREPARED_CI_WORKFLOW="$prepared_pull_request" \
  "$PREPARE_CI_APP" "$output_file"
[[ $(cut -d= -f1 "$output_file") == workflow ]]
[[ $(cut -d= -f2- "$output_file") == "$prepared_pull_request" ]]
if XO_NIXPKG_RUNTIME_NIX="$temporary_directory/bin/runtime-nix" \
  FAKE_PREPARED_CI_WORKFLOW="$prepared_pull_request" \
  "$PREPARE_CI_APP" one two >/dev/null 2>&1; then
  echo 'prepare-ci accepted too many arguments' >&2
  exit 1
fi

printf '#!%s\n' "$BASH" >"$temporary_directory/bin/classify-ci"
cat >>"$temporary_directory/bin/classify-ci" <<'EOF'
set -euo pipefail
printf '%s\n' "$FAKE_LIFECYCLE_WORKFLOW"
EOF
chmod +x "$temporary_directory/bin/classify-ci"

printf '#!%s\n' "$BASH" >"$temporary_directory/bin/nix"
cat >>"$temporary_directory/bin/nix" <<'EOF'
set -euo pipefail
printf 'nix'
printf ' <%s>' "$@"
printf '\n'
EOF
chmod +x "$temporary_directory/bin/nix"

printf '#!%s\n' "$BASH" >"$temporary_directory/bin/flake-plan-runner"
cat >>"$temporary_directory/bin/flake-plan-runner" <<'EOF'
set -euo pipefail
manifest=
printf 'flake-plan-runner'
while (( $# > 0 )); do
  printf ' <%s>' "$1"
  if [[ $1 == --manifest ]]; then
    manifest=$2
  fi
  shift
done
printf '\n'
if [[ -n $manifest ]]; then
  printf '%s\n' '{"results":[{"outputs":["/nix/store/xo"]},{"outputs":["/nix/store/libvhdi"]}]}' >"$manifest"
fi
EOF
chmod +x "$temporary_directory/bin/flake-plan-runner"

printf '#!%s\n' "$BASH" >"$temporary_directory/bin/cachix"
cat >>"$temporary_directory/bin/cachix" <<'EOF'
set -euo pipefail
printf 'cachix'
printf ' <%s>' "$@"
printf '\n'
EOF
chmod +x "$temporary_directory/bin/cachix"

PATH="$temporary_directory/bin:$PATH" \
FAKE_LIFECYCLE_WORKFLOW="$prepared_lifecycle" \
XO_NIXPKG_CLASSIFY_CI_COMMAND="$temporary_directory/bin/classify-ci" \
XO_NIXPKG_SOURCE_ROOT="$root" \
  bash "$root/ci/run.sh" >"$temporary_directory/validation-log"
[[ $(<"$temporary_directory/validation-log") == \
  *'<--plan-file>'* ]]

PATH="$temporary_directory/bin:$PATH" \
CACHIX_AUTH_TOKEN=fixture \
PREPARED_CI_WORKFLOW="$prepared_lifecycle" \
  bash "$root/ci/publish.sh" >"$temporary_directory/publish-log"
[[ $(<"$temporary_directory/publish-log") == \
  *'<--plan-file>'* ]]
[[ $(<"$temporary_directory/publish-log") == \
  *'cachix <push> <xen-orchestra-ce> </nix/store/xo> </nix/store/libvhdi>'* ]]

printf 'CI runtime fixtures passed\n'
