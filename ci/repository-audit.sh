#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
exec nix flake check --accept-flake-config --no-write-lock-file "$@"
