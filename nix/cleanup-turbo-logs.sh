#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
[[ $# == 1 && -d $1 && ! -L $1 ]]
# find does not follow symlinks. Preserve every other file and runtime asset.
find "$1" -type f -path '*/.turbo/turbo-build.log' -delete
