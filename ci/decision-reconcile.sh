#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${XO_NIXPKG_EVIDENCE:?}"
xo-nixpkg-decision-reconcile --config ci/decision-policy.json \
  --scans "$XO_NIXPKG_EVIDENCE/scans.json" \
  --product "$XO_NIXPKG_EVIDENCE/product.json" \
  --directory "$XO_NIXPKG_EVIDENCE" \
  --kind "${XO_NIXPKG_PROPOSAL_KIND:-security-findings}"
