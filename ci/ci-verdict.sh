#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[[ ${CLASSIFY_RESULT:?} == success ]]
if [[ -n ${PREFLIGHT_RESULT:-} ]]; then
  [[ $PREFLIGHT_RESULT == success ]]
fi
if [[ ${VALIDATE_ENABLED:?} == true ]]; then
  [[ ${VALIDATE_RESULT:?} == success ]]
else
  [[ ${VALIDATE_RESULT:?} == skipped ]]
fi
