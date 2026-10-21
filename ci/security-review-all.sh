#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
output=${SECURITY_OUTPUT:-security-report}
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/advisory-inputs.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/inputs"
if [[ -n ${GH_TOKEN:-} && -n ${REGISTRY_TOKEN:-} ]]; then
  status=0
  python3 "$XO_ADVISORY_INPUTS_SOURCE" "$work/inputs" || status=$?
  if [[ $status == 4 ]]; then
    echo 'No exact-source signed inventory is eligible; retaining complete supply inventory coverage.'
  elif [[ $status != 0 ]]; then exit "$status"
  fi
fi
# Builders and advisory scanners receive no API or publication credentials.
unset GH_TOKEN GITHUB_TOKEN REGISTRY_TOKEN CACHIX_AUTH_TOKEN DECIDER_KEY XO_AUTHORITY_TOKEN \
  SECAUDIT_PEM ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_RUNTIME_TOKEN MERGE_QUEUE_TOKEN
export XO_SECURITY_DATABASE="$work/database"
XO_SECURITY_DATABASE_RECEIPT=$(python3 "${XO_OPERATIONS_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/operations.py}" --timeout 900 -- xo-nixpkg-security-database prepare "$XO_SECURITY_DATABASE" --max-age-hours 24)
export XO_SECURITY_DATABASE_RECEIPT XO_SECURITY_SHARED_INPUTS="$work/inputs"
status=0
for channel in latest stable rolling; do
  channel_status=0
  SECURITY_OUTPUT="$output/$channel" xo-nixpkg-security-scan "$channel" || channel_status=$?
  if [[ $channel_status != 0 ]]; then status=2; fi
done
python3 "${XO_OPERATIONS_SOURCE:-$(dirname -- "${BASH_SOURCE[0]}")/decisions/operations.py}" --timeout 30 -- xo-nixpkg-security-database verify "$XO_SECURITY_DATABASE" "$XO_SECURITY_DATABASE_RECEIPT" --max-age-hours 24
exit "$status"
