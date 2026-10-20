#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
inventory=${1:?inventory directory required}
output=${2:?output directory required}
mkdir -p "$output"
rm -f "$output/scan.json"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
for variable in "${!GRYPE_@}"; do unset "$variable"; done
export GRYPE_DB_CACHE_DIR="$work/db"
export GRYPE_DB_MAX_ALLOWED_BUILT_AGE=48h GRYPE_DB_VALIDATE_AGE=true
export GRYPE_DB_AUTO_UPDATE=true GRYPE_DB_REQUIRE_UPDATE_CHECK=true
printf '{}\n' >"$work/grype.yaml"
cat >"$work/probe.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"openssl","version":"1.0.1","purl":"pkg:nix/openssl@1.0.1"},{"type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}]}
JSON
grype --config "$work/grype.yaml" "sbom:$work/probe.json" --add-cpes-if-none -o json >"$output/probe.grype.json"
jq -e 'any(.matches[]; .artifact.name == "openssl") and any(.matches[]; .artifact.name == "lodash")' "$output/probe.grype.json" >/dev/null
grype --config "$work/grype.yaml" "sbom:$inventory/runtime.cdx.json" --add-cpes-if-none -o json >"$output/runtime.grype.json"
grype --config "$work/grype.yaml" db status -o json >"$output/database.json"
jq -e '.valid == true' "$output/database.json" >/dev/null
python3 "$XO_NIXPKG_SECURITY_NORMALIZER" "$inventory" "$output"
