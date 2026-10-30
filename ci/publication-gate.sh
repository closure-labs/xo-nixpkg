#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${XO_NIXPKG_EVIDENCE:?XO_NIXPKG_EVIDENCE must identify attested candidate evidence}"
: "${XO_NIXPKG_PUBLICATION_PURPOSE:?Set publication purpose rolling or release}"
python3 "${XO_NIXPKG_AUDIT_FRESHNESS_SOURCE:?}"
# This command queries current-main policy and human authority each invocation.
# A previously generated receipt can never substitute for this check.
exec xo-nixpkg-decision-publication \
  --config "$XO_NIXPKG_SOURCE_ROOT/ci/decision-policy.json" \
  --scans "$XO_NIXPKG_EVIDENCE/scans.json" \
  --product "$XO_NIXPKG_EVIDENCE/product.json" \
  --purpose "$XO_NIXPKG_PUBLICATION_PURPOSE"
