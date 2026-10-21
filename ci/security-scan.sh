#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[[ $# -le 1 ]] || { echo 'Usage: security-scan [latest|stable|rolling]' >&2; exit 2; }
channel=${1:-${CHANNEL:-latest}}
case $channel in latest|stable|rolling) ;; *) echo 'Unknown XO channel.' >&2; exit 2 ;; esac
mode=${SECURITY_MODE:-report}
case $mode in report|enforce) ;; *) echo 'Unknown security mode.' >&2; exit 2 ;; esac
: "${XO_SECURITY_NORMALIZE_SOURCE:?}" "${XO_SECURITY_APPLICABILITY_RULES:?}"
repo_root=${XO_NIXPKG_SOURCE_ROOT:-$PWD}
output=${SECURITY_OUTPUT:-security-report/$channel}
mkdir -p "$output"
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/xo-security.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
# A failed invocation must not leave a previous successful verdict behind.
rm -f -- "$output/critical-applicability.json" "$output/unresolved-critical.json" "$output/summary.json"
flake="git+file://$repo_root"
protector=$(nix build --accept-flake-config --no-write-lock-file --no-link --print-out-paths \
  "$flake#supply-protector-$channel")
[[ $protector =~ ^/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[^/[:space:]]+$ ]]
nix eval --accept-flake-config --no-write-lock-file --json \
  "$flake#supply-protector-$channel" \
  --apply 'package: { root = package.protectedPackage.outPath; inherit (package) channel sourceRev version; }' \
  >"$output/expected-package.json"
python3 "$XO_SECURITY_NORMALIZE_SOURCE" verify "$protector" "$output/expected-package.json" "$output/context.json"
cp "$protector/xen-orchestra.cdx.json" "$output/inventory.cdx.json"
cp "$protector/assertion.json" "$output/assertion.json"
# Every invocation uses a fresh, age-validated database. Canary failures are
# infrastructure failures even in report mode; no finding is hidden by them.
if [[ -n ${XO_SECURITY_DATABASE:-} ]]; then
  python3 "${XO_OPERATIONS_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/operations.py}" --timeout 30 -- xo-nixpkg-security-database verify "$XO_SECURITY_DATABASE" "${XO_SECURITY_DATABASE_RECEIPT:?}" --max-age-hours 24
  for variable in "${!GRYPE_@}"; do unset "$variable"; done
  export GRYPE_DB_CACHE_DIR="$XO_SECURITY_DATABASE/db"
  export GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_REQUIRE_UPDATE_CHECK=false
  grype() { command grype --config "$XO_SECURITY_DATABASE/grype.yaml" "$@"; }
else
  export GRYPE_DB_CACHE_DIR="$work/grype-db"
fi
export GRYPE_DB_MAX_ALLOWED_BUILT_AGE=24h
export GRYPE_DB_VALIDATE_AGE=true
grype version -o json >"$output/grype-version.json"
cat >"$work/scanner-check.cdx.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
  {"type":"library","name":"openssl","version":"1.0.1","bom-ref":"native-canary","purl":"pkg:nix/openssl@1.0.1"},
  {"type":"library","name":"lodash","version":"4.17.15","bom-ref":"npm-canary","purl":"pkg:npm/lodash@4.17.15"}
]}
JSON
grype "sbom:$work/scanner-check.cdx.json" --add-cpes-if-none -o json >"$output/scanner-check.grype.json"
jq -e 'any(.matches[]; .artifact.name == "openssl") and any(.matches[]; .artifact.name == "lodash")' \
  "$output/scanner-check.grype.json" >/dev/null
if [[ -n ${XO_SECURITY_SHARED_INPUTS:-} && -f $XO_SECURITY_SHARED_INPUTS/shared-inventories.json ]]; then
  python3 "$XO_ADVISORY_UNION_SOURCE" "$output/inventory.cdx.json" "$XO_SECURITY_SHARED_INPUTS" "$channel"
fi
grype "sbom:$output/inventory.cdx.json" --add-cpes-if-none -o json >"$output/raw.grype.json"
python3 "$XO_SECURITY_NORMALIZE_SOURCE" normalize "$output/raw.grype.json" "$output/inventory.cdx.json" \
  "$output/grype-version.json" "$output/context.json" "$output/findings.json"
if [[ -n ${XO_SECURITY_DATABASE:-} ]]; then
  python3 "${XO_OPERATIONS_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/operations.py}" --timeout 30 -- xo-nixpkg-security-database verify "$XO_SECURITY_DATABASE" "$XO_SECURITY_DATABASE_RECEIPT" --max-age-hours 24
fi
applicability_status=0
xo-nixpkg-security-applicability --findings "$output/findings.json" --inventory "$output/inventory.cdx.json" \
  --context "$output/context.json" --rules "$XO_SECURITY_APPLICABILITY_RULES" \
  --output "$output/critical-applicability.json" --mode "$mode" || applicability_status=$?
[[ $applicability_status == 0 || $applicability_status == 1 && $mode == enforce ]]
jq '.unresolved_critical' "$output/critical-applicability.json" >"$output/unresolved-critical.json"
jq --arg channel "$channel" --arg mode "$mode" \
  '{channel:$channel,mode:$mode,total:(.results | length),unresolved_critical:(.unresolved_critical | length),
    reviewed:(.dispositions | length)}' "$output/critical-applicability.json" >"$output/summary.json"
if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
  jq -r '"XO \(.channel): \(.total) findings, \(.unresolved_critical) unresolved critical; mode \(.mode)."' \
    "$output/summary.json" >>"$GITHUB_STEP_SUMMARY"
fi
cat "$output/summary.json"
exit "$applicability_status"
