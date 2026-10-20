#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rescan retained immutable products using current trusted scanners, without rebuilding source."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    source = Path(os.environ['XO_NIXPKG_RESCAN_SOURCE'])
    output = Path(os.environ.get('XO_NIXPKG_EVIDENCE', 'security-evidence'))
    product = json.loads((source / 'product.json').read_text())
    # Fetch wrapper authenticated the immutable product before credentials were removed.
    for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'CACHIX_AUTH_TOKEN', 'REGISTRY_TOKEN'):
        os.environ.pop(key, None)
    previous_scan = json.loads((source / 'scans.json').read_text())
    spec = importlib.util.spec_from_file_location('distribution_cache', os.environ['XO_NIXPKG_DISTRIBUTION_CACHE_SOURCE'])
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    all_roots = [*product['products'].values(), *({'storePath': r['storePath'], 'narHash': r['narHash']} for r in product.get('roots', {}).values())]
    transport.restore(source, previous_scan['transport'], all_roots)
    if output.exists():
        raise ValueError('refresh output directory must be fresh')
    if any(path.is_symlink() for path in source.rglob('*')):
        raise ValueError('retained evidence contains a forbidden symbolic link')
    for name, expected in product['assets'].items():
        path = source / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('retained immutable inventory differs from signed product')
    shutil.copytree(source, output, symlinks=False)
    started = datetime.datetime.now(datetime.timezone.utc)
    profiles = {}
    for profile, root in product['products'].items():
        subjects = [root, *({k: v for k, v in extra.items() if k != 'profile'}
                           for extra in product.get('roots', {}).values() if extra['profile'] == profile)]
        for subject in subjects:
            path = subject['storePath']
            subprocess.run(['nix-store', '--realise', path], check=True)
            response = json.loads(command('nix', 'path-info', '--json', path))
            actual = response[0] if isinstance(response, list) else response[path]
            if actual['narHash'] != subject['narHash']:
                raise ValueError('retained output NAR hash mismatch')
        directory = output / profile
        # Inventory is copied from an immutable product asset and includes exact
        # deployed paths. Raw scanner output is replaced with fresh observations.
        flat_inventory = output / (profile + '--runtime.cdx.json')
        if (directory / 'runtime.cdx.json').read_bytes() != flat_inventory.read_bytes():
            raise ValueError('runtime inventory differs from authenticated product asset')
        subprocess.run(['xo-nixpkg-security-native-scan', str(directory), str(directory)], check=True)
        profiles[profile] = json.loads((directory / 'scan.json').read_text())
        profiles[profile]['subjects'] = subjects
    scan = {'schema': 1, 'repository': product['repository'], 'revision': product['revision'],
            'producer': {'workflow': '.github/workflows/qualification.yml',
                         'revision': command('git', 'rev-parse', 'HEAD'),
                         'runId': int(os.environ['GITHUB_RUN_ID']), 'runAttempt': int(os.environ['GITHUB_RUN_ATTEMPT'])},
            'scannedAt': started.isoformat(), 'expiresAt': (started + datetime.timedelta(hours=48)).isoformat(),
            'profiles': profiles, 'transport': previous_scan['transport'],
            'productProducer': previous_scan.get('productProducer', dict(previous_scan['producer'],
                revision=previous_scan['producer'].get('revision', product['revision'])))}
    (output / 'scans.json').write_text(json.dumps(scan, sort_keys=True, indent=2) + '\n')
    for profile in product['products']:
        handoff = {'schema': 1, 'repository': product['repository'], 'revision': product['revision'],
                   'channel': profile, 'product': product, 'scans': scan}
        (output / f'handoff-{profile}.json').write_text(json.dumps(handoff, sort_keys=True, indent=2) + '\n')
    if (output / 'product.json').read_bytes() != (source / 'product.json').read_bytes():
        raise ValueError('immutable release product changed during refresh')


if __name__ == '__main__':
    main()
