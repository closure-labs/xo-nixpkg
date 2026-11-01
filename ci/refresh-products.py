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
import tempfile


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def native_binding():
    path = os.environ.get('XO_NATIVE_SECRET_CONTROLLER_SOURCE', str(Path(__file__).with_name('native-secret-controller.py')))
    spec = importlib.util.spec_from_file_location('native_secret_policy', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.policy_binding()


def main():
    source = Path(os.environ['XO_NIXPKG_RESCAN_SOURCE'])
    output = Path(os.environ.get('XO_NIXPKG_EVIDENCE', 'security-evidence'))
    product = json.loads((source / 'product.json').read_text())
    if product.get('repositorySecretPolicy') != native_binding():
        raise ValueError('New policy requires fresh product qualification, not a legacy rescan')
    # Fetch wrapper authenticated the immutable product before credentials were removed.
    for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'CACHIX_AUTH_TOKEN', 'REGISTRY_TOKEN',
                'SECAUDIT_PEM', 'DECIDER_KEY', 'XO_AUTHORITY_TOKEN',
                'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'NATIVE_SECRET_OBSERVER_TOKEN'):
        os.environ.pop(key, None)
    previous_scan = json.loads((source / 'scans.json').read_text())
    if output.exists():
        raise ValueError('refresh output directory must be fresh')
    if any(path.is_symlink() for path in source.rglob('*')):
        raise ValueError('retained evidence contains a forbidden symbolic link')
    # product/scans were authenticated by the fetch wrapper. Enforce complete
    # inventory bytes again before scanning; no store realization is needed.
    if not product.get('assets') or len(product['assets']) > 256:
        raise ValueError('Missing or oversized immutable inventory manifest')
    total = 0
    for name, expected in product['assets'].items():
        if not isinstance(name, str) or not __import__('re').fullmatch(r'[A-Za-z0-9_.+-]+', name):
            raise ValueError('Unsafe immutable inventory asset')
        path = source / name
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 64 * 1024**2:
            raise ValueError('Retained immutable inventory absent or oversized')
        total += path.stat().st_size
        if total > 512 * 1024**2 or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('retained immutable inventory differs from signed product')
    output.mkdir()
    # Copy only authenticated immutable inventory assets, never old raw reports,
    # aggregate success, handoffs or multi-GiB closure parts.
    for name in ('product.json', *product['assets']):
        shutil.copyfile(source / name, output / name)
    started = datetime.datetime.now(datetime.timezone.utc)
    profiles = {}
    with tempfile.TemporaryDirectory(prefix='xo-security-db-') as temporary:
        snapshot = Path(temporary) / 'snapshot'
        database_receipt = command('xo-nixpkg-security-database', 'prepare', str(snapshot))
        for profile, root in product['products'].items():
            subjects = [root, *({k: v for k, v in extra.items() if k != 'profile'}
                               for extra in product.get('roots', {}).values() if extra['profile'] == profile)]
            directory = output / profile
            directory.mkdir(exist_ok=True)
            flat_inventory = output / (profile + '--runtime.cdx.json')
            if flat_inventory.name not in product['assets']:
                raise ValueError('Profile runtime inventory missing from signed product')
            # Reconstruct scanner input ONLY from the authenticated flat asset.
            (directory / 'runtime.cdx.json').write_bytes(flat_inventory.read_bytes())
            subprocess.run(['xo-nixpkg-security-native-scan', str(directory), str(directory),
                            '--database', str(snapshot), '--database-receipt-sha256', database_receipt], check=True)
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
    scan['repositorySecretPolicy'] = native_binding()
    (output / 'scans.json').write_text(json.dumps(scan, sort_keys=True, indent=2) + '\n')
    for profile in product['products']:
        handoff = {'schema': 1, 'repository': product['repository'], 'revision': product['revision'],
                   'channel': profile, 'product': product, 'scans': scan}
        (output / f'handoff-{profile}.json').write_text(json.dumps(handoff, sort_keys=True, indent=2) + '\n')
    if (output / 'product.json').read_bytes() != (source / 'product.json').read_bytes():
        raise ValueError('immutable release product changed during refresh')


if __name__ == '__main__':
    main()
