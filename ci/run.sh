#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=${XO_NIXPKG_SOURCE_ROOT:-$PWD}

exec nix flake check \
  --accept-flake-config \
  --no-write-lock-file \
  --print-build-logs \
  "git+file://$repo_root" \
  "$@"
