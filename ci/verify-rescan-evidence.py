#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Authenticate historical evidence before reusing private NAR bytes for a rescan."""
import os
from pathlib import Path
from common import config, scans, product


def main():
    cfg = config(Path('ci/decision-policy.json'), live=True)
    directory = Path(os.environ['XO_NIXPKG_EVIDENCE'])
    native = scans(directory / 'scans.json', cfg, allow_expired=True)
    product(directory / 'product.json', cfg, native)


if __name__ == '__main__':
    main()
