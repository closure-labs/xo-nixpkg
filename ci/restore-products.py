#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Restore only authenticated, digest-bound private NAR transport; never build."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess


def main():
    subprocess.run(['xo-nixpkg-publication-gate'], check=True)
    directory = Path(os.environ['XO_NIXPKG_EVIDENCE'])
    product = json.loads((directory / 'product.json').read_text())
    scan = json.loads((directory / 'scans.json').read_text())
    spec = importlib.util.spec_from_file_location('distribution_cache', os.environ['XO_NIXPKG_DISTRIBUTION_CACHE_SOURCE'])
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    roots = [*product['products'].values(), *({'storePath': r['storePath'], 'narHash': r['narHash']} for r in product.get('roots', {}).values())]
    transport.restore(directory, scan['transport'], roots)


if __name__ == '__main__':
    main()
