#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if (( $# > 1 )); then
  echo 'usage: update-flake-lock.sh [GITHUB_OUTPUT]' >&2
  exit 2
fi

before=$(sha256sum flake.lock devenv.lock)
# XO channel sources have dedicated updaters. Refresh only the development
# inputs here, including the non-flake native environment's lock.
nix run --accept-flake-config .#devenv -- update
nix flake update nixpkgs --accept-flake-config
jq -e -s '
  def identity($lock; $input):
    $lock.nodes[$lock.nodes.root.inputs[$input]].locked | {type, rev, narHash} |
    if all(.[]; type == "string" and length > 0) then .
    else error("missing locked identity") end;
  . as $locks |
  all(["nixpkgs"][];
    . as $input | identity($locks[0]; $input) == identity($locks[1]; $input))
' flake.lock devenv.lock >/dev/null || {
  echo 'flake.lock and devenv.lock must share the nixpkgs identity' >&2
  exit 1
}
after=$(sha256sum flake.lock devenv.lock)
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
