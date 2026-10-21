#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Only transport is bounded here. Waiting for hosted builds retains its own policy.
limit=30
case "${1:-} ${2:-}" in
  'run watch') exec @GH@ "$@" ;;
  'run download') limit=900 ;;
  'attestation verify') limit=90 ;;
  'release upload') limit=1800 ;;
esac
for argument in "$@"; do
  case $argument in */zip|*/releases/assets/*) limit=900 ;; esac
done
exec @PYTHON@ @OPERATIONS@ --timeout "$limit" -- @GH@ "$@"
