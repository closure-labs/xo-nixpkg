#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Materialize authenticated original transport once; restore exact NARs, never build."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile


def materialize(directory, product, scan, transport):
    parts = scan['transport'].get('parts', {})
    if not isinstance(parts, dict) or not parts:
        raise ValueError('Original closure part manifest is missing')
    present = [name for name in parts if (directory / name).exists()]
    if present:
        # A partial or changed local transport must not be silently repaired.
        transport.validate_manifest(directory, scan['transport'])
        return
    original = scan.get('productProducer')
    if not isinstance(original, dict) or any(type(original.get(k)) is not int or original[k] <= 0 for k in ('runId', 'runAttempt')):
        raise ValueError('Original closure producer is missing')
    # The live publication gate authenticates productProducer. The same existing
    # fetch/verifier repeats provenance checks and retained recovery for that run.
    with tempfile.TemporaryDirectory(prefix='xo-publication-closure-') as temporary:
        source = Path(temporary) / 'evidence'
        env = dict(os.environ, QUALIFICATION_RUN=str(original['runId']),
                   QUALIFICATION_ATTEMPT=str(original['runAttempt']),
                   XO_NIXPKG_EVIDENCE=str(source), XO_NIXPKG_FETCH_FOR_RESCAN='true',
                   XO_NIXPKG_FETCH_FULL_TRANSPORT='true', XO_NIXPKG_PUBLICATION_METADATA_ONLY='false',
                   XO_NIXPKG_RESCAN_INVENTORY_ONLY='false')
        subprocess.run(['xo-nixpkg-fetch-evidence'], env=env, check=True)
        if (source / 'product.json').read_bytes() != (directory / 'product.json').read_bytes():
            raise ValueError('Original closure product differs from approved product')
        original_scan = json.loads((source / 'scans.json').read_text())
        if original_scan.get('transport') != scan['transport']:
            raise ValueError('Original closure transport differs from approved observation')
        names = transport.validate_manifest(source, scan['transport'])
        from decision_packets import install_member
        for name in names:
            install_member(source / name, directory / name, directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--materialize-only', action='store_true')
    args = parser.parse_args()
    subprocess.run(['xo-nixpkg-publication-gate'], check=True)
    directory = Path(os.environ['XO_NIXPKG_EVIDENCE'])
    product = json.loads((directory / 'product.json').read_text())
    scan = json.loads((directory / 'scans.json').read_text())
    spec = importlib.util.spec_from_file_location('distribution_cache', os.environ['XO_NIXPKG_DISTRIBUTION_CACHE_SOURCE'])
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    roots = [*product['products'].values(), *({'storePath': r['storePath'], 'narHash': r['narHash']} for r in product.get('roots', {}).values())]
    materialize(directory, product, scan, transport)
    if not args.materialize_only:
        transport.restore(directory, scan['transport'], roots)


if __name__ == '__main__':
    main()
