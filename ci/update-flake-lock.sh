#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if (( $# > 1 )); then
  echo 'usage: update-flake-lock.sh [GITHUB_OUTPUT]' >&2
  exit 2
fi

before=$(sha256sum flake.lock | cut -d ' ' -f1)
nix flake update nixpkgs --accept-flake-config
after=$(sha256sum flake.lock | cut -d ' ' -f1)
changed=false
if [[ $before != "$after" ]]; then
  changed=true
  nix flake check --accept-flake-config --no-build --no-write-lock-file
fi

if (( $# == 1 )); then
  printf 'changed=%s\n' "$changed" >>"$1"
else
  printf 'changed=%s\n' "$changed"
fi
