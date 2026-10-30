#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# Pure repository checks only. The standalone read-only Gitleaks workflow owns
# incoming scans; publication retains its separate live native observation.
nix build --no-link --no-write-lock-file .#lib.ciSecurityFixtures.x86_64-linux
