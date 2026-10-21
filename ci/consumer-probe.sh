#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
exec python3 "$XO_NIXPKG_CONSUMER_PROBE_SOURCE" --config ci/decision-policy.json \
  --cache https://xen-orchestra-ce.cachix.org --key 'xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E='
