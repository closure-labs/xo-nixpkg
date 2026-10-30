#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# Pure repository checks only. Authenticated native observations are separately
# owned by protected-main native-secret-observation.yml, never candidate code.
nix build --no-link --no-write-lock-file .#lib.ciSecurityFixtures.x86_64-linux
