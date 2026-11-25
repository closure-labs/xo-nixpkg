#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Enforce shared findings validation inside the required language analysis job."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).with_name('decisions')))
import common
import codeql_findings

if __name__ == '__main__':
    sys.exit(common.run(codeql_findings.main))
