#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# Shared pure checks. History scanning belongs to the native security owner.
python3 ci/decisions/signal_relay.py .github/workflows/decision-events.yml
actionlint -ignore 'unexpected key "queue"' .github/workflows/*.yml
zizmor .github
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s tests/decisions -p 'test_*.py'
python3 tests/distribution-cache.py
