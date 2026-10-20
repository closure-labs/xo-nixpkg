#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[[ ${CLASSIFY_RESULT:?} == success ]]
if [[ ${VALIDATE_ENABLED:?} == true ]]; then
  [[ ${VALIDATE_RESULT:?} == success ]]
else
  [[ ${VALIDATE_RESULT:?} == skipped ]]
fi
