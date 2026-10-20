#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${GH_TOKEN:?Missing short-lived Decider queue token}"
: "${GITHUB_REPOSITORY:?}"
gh api "repos/${GITHUB_REPOSITORY}/actions/runs?per_page=1" >/dev/null
gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&per_page=1" >/dev/null
