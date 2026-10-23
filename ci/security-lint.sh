#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[[ $(git rev-parse --is-shallow-repository) == false ]]
gitleaks git --redact --no-banner
nix build --no-link --no-write-lock-file .#lib.ciSecurityFixtures.x86_64-linux
