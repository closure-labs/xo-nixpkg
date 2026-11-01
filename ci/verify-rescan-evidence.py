#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Authenticate historical evidence before reusing private NAR bytes for a rescan."""
import os
import hashlib
import stat
from pathlib import Path
from common import config, scans, product


def main():
    cfg = config(Path('ci/decision-policy.json'), live=True)
    directory = Path(os.environ['XO_NIXPKG_EVIDENCE'])
    native = scans(directory / 'scans.json', cfg, allow_expired=True)
    immutable = product(directory / 'product.json', cfg, native)
    if os.environ.get('XO_NIXPKG_FETCH_FULL_TRANSPORT') != 'true':
        expected = {'product.json', 'scans.json', *immutable['assets']}
        if {p.name for p in directory.iterdir()} != expected:
            raise ValueError('Inventory-only artifact has missing or unexpected members')
        total = 0
        for name in expected:
            path = directory / name
            limit = (128 if name == 'scans.json' else 16 if name == 'product.json' else 64) * 1024**2
            if not stat.S_ISREG(path.lstat().st_mode) or not 0 < path.stat().st_size <= limit:
                raise ValueError('Inventory-only member is not regular or exceeds bound')
            total += path.stat().st_size
            if total > 512 * 1024**2:
                raise ValueError('Inventory-only artifact exceeds aggregate bound')
            if name in immutable['assets']:
                with path.open('rb') as stream:
                    actual = hashlib.file_digest(stream, 'sha256').hexdigest()
                if actual != immutable['assets'][name]:
                    raise ValueError('Inventory-only asset differs from authenticated product')


if __name__ == '__main__':
    main()
