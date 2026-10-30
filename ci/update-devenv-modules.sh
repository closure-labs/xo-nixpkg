#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Explicit local maintenance: Dependabot, not this command, owns nixpkgs.
set -euo pipefail
(( $# <= 1 )) || { echo 'usage: update-devenv-modules.sh [GITHUB_OUTPUT]' >&2; exit 2; }
before=$(sha256sum flake.lock)
saved=$(mktemp)
trap 'rm -f -- "$saved"' EXIT
cp devenv.lock "$saved"
nix run --accept-flake-config .#devenv -- update devenv
[[ $(sha256sum flake.lock) == "$before" ]] || { echo 'Native module update changed flake.lock' >&2; exit 1; }
python3 - "$saved" <<'PY'
import copy, json, sys
from pathlib import Path
old, new, flake = [json.loads(Path(p).read_text()) for p in (sys.argv[1], 'devenv.lock', 'flake.lock')]
module = old['nodes'][old['root']]['inputs']['devenv']
expected = copy.deepcopy(old)
expected['nodes'][module]['locked'] = new['nodes'][module]['locked']
if expected != new:
    sys.exit('Native module maintenance must not change unrelated inputs')
def pkgs(lock):
    return lock['nodes'][lock['nodes'][lock['root']]['inputs']['nixpkgs']]
if pkgs(old) != pkgs(new) or pkgs(new) != pkgs(flake):
    sys.exit('Native module maintenance must preserve the paired nixpkgs identity')
PY
changed=false
if ! cmp -s "$saved" devenv.lock; then
  changed=true
  nix flake check --accept-flake-config --no-build --no-write-lock-file
fi
if (( $# == 1 )); then printf 'changed=%s\n' "$changed" >>"$1"; else printf 'changed=%s\n' "$changed"; fi
