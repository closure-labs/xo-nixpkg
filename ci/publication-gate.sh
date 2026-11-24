#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${XO_NIXPKG_EVIDENCE:?XO_NIXPKG_EVIDENCE must identify attested candidate evidence}"
: "${XO_NIXPKG_PUBLICATION_PURPOSE:?Set publication purpose rolling or release}"
python3 "${XO_NIXPKG_AUDIT_FRESHNESS_SOURCE:?}"
# Native PR rules authorize the request merged on protected main.
# Revalidate exact planned bytes, health and live protection at every write.
exec xo-nixpkg-publication-plan gate
