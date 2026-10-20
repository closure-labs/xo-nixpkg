#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${COLLECTOR_RUN:?}"
if [[ -n ${REGISTRY_TOKEN:-} ]]; then
  printf '%s' "$REGISTRY_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
  trap 'oras logout ghcr.io >/dev/null 2>&1 || true' EXIT
fi
xo-nixpkg-decision-check --config ci/decision-policy.json --collector-run "$COLLECTOR_RUN"
