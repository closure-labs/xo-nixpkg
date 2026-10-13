#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Sourced by fetchYarnDeps. Each attempt uses the original checksum validator.
prefetch-yarn-deps() {
  local attempt temporary status
  for attempt in 1 2 3; do
    temporary=$(mktemp -d) || return
    if (cd "$temporary" && command prefetch-yarn-deps "$@"); then
      # Publish only a complete, verified cache. Never reuse failed downloads.
      if cp -a "$temporary/." .; then
        rm -rf -- "$temporary"
        return 0
      else
        status=$?
        rm -rf -- "$temporary"
        return "$status"
      fi
    else
      status=$?
    fi
    rm -rf -- "$temporary"
    echo "Yarn dependency fetch attempt $attempt/3 failed (status $status)" >&2
    if ((attempt < 3)); then
      sleep "$((attempt * 5))"
    fi
  done
  return "$status"
}
