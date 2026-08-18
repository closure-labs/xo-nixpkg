#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

bash "$root/tests/policy.sh"
bash "$root/tests/update-xo.sh"
bash "$root/tests/update-libvhdi.sh"
bash "$root/tests/update-noop.sh"
bash "$root/tests/trusted-update.sh"
bash "$root/tests/tag-release.sh"
bash "$root/tests/flake-attribute-validator.sh"

printf 'Repository fixtures passed\n'
