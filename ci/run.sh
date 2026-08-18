#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=${XO_NIXPKG_SOURCE_ROOT:-$PWD}
flake_ref="git+file://$repo_root"

nix flake check \
  --accept-flake-config \
  --no-build \
  --no-write-lock-file \
  --print-build-logs \
  "$flake_ref" \
  "$@"

exec flake-plan-runner \
  --flake "$flake_ref" \
  --plan "${XO_NIXPKG_CI_PLAN:?XO_NIXPKG_CI_PLAN must be set}"
