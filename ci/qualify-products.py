#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build, inventory and scan each independently distributed output without credentials."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def native_binding():
    path = os.environ.get('XO_NATIVE_SECRET_CONTROLLER_SOURCE', str(Path(__file__).with_name('native-secret-controller.py')))
    spec = importlib.util.spec_from_file_location('native_secret_policy', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.policy_binding()


def main():
    output = Path(os.environ.get('XO_NIXPKG_EVIDENCE', 'security-evidence'))
    if output.exists():
        raise ValueError('qualification requires a fresh evidence directory')
    output.mkdir(parents=True)
    # Reuse is identity-only and uses an independently authenticated producer.
    # The helper isolates candidate evaluation from this read credential.
    subprocess.run(['xo-nixpkg-build-reuse', 'restore', '--candidate', str(Path.cwd()),
                    '--controller', str(Path.cwd()), '--output', str(output / 'build-reuse.json')], check=True)
    for name in ('GH_TOKEN', 'GITHUB_TOKEN', 'CACHIX_AUTH_TOKEN', 'SECAUDIT_PEM',
                 'REGISTRY_TOKEN', 'DECIDER_KEY', 'XO_AUTHORITY_TOKEN',
                 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'NATIVE_SECRET_OBSERVER_TOKEN'):
        os.environ.pop(name, None)
    revision = run('git', 'rev-parse', 'HEAD')
    started = datetime.datetime.now(datetime.timezone.utc)
    profiles = {}
    products = {}
    roots = {}
    with tempfile.TemporaryDirectory(prefix='xo-security-db-') as temporary:
        snapshot = Path(temporary) / 'snapshot'
        database_receipt = run('xo-nixpkg-security-database', 'prepare', str(snapshot))
        for profile, attribute in [('xo-latest', 'latest'), ('xo-stable', 'stable'), ('xo-rolling', 'rolling'), ('libvhdi', 'libvhdi')]:
            root = run('nix', 'build', '--accept-flake-config', '--no-link', '--print-out-paths', '.#' + attribute)
            if '\n' in root or not root.startswith('/nix/store/'):
                raise ValueError('expected exactly one immutable product output')
            directory = output / profile
            additional = []
            if profile != 'libvhdi':
                assertion = run('nix', 'build', '--accept-flake-config', '--no-link', '--print-out-paths', '.#supply-protector-' + attribute)
                additional.append(('supply-protector-' + attribute, assertion))
            if profile == 'xo-latest':
                additional.append(('automation-runtime', run('nix', 'build', '--accept-flake-config', '--no-link', '--print-out-paths', '.#automation-runtime')))
            inventory_args = ['xo-nixpkg-security-inventory', '--root', root, '--profile', profile, '--output', str(directory)]
            for _, extra_root in additional:
                inventory_args += ['--additional-root', extra_root]
            subprocess.run(inventory_args, check=True)
            subprocess.run(['xo-nixpkg-security-native-scan', str(directory), str(directory),
                            '--database', str(snapshot), '--database-receipt-sha256', database_receipt], check=True)
            profiles[profile] = json.loads((directory / 'scan.json').read_text())
            info = json.loads(run('nix', 'path-info', '--json', root))
            item = info[0] if isinstance(info, list) else info[root]
            products[profile] = {'storePath': root, 'narHash': item['narHash']}
            profiles[profile]['subjects'] = [products[profile]]
            for name, path in additional:
                extra_info = json.loads(run('nix', 'path-info', '--json', path))
                extra_item = extra_info[0] if isinstance(extra_info, list) else extra_info[path]
                roots[name] = {'storePath': path, 'narHash': extra_item['narHash'], 'profile': profile}
                profiles[profile]['subjects'].append({'storePath': path, 'narHash': extra_item['narHash']})
            # Preserve existing reproducible closure assertion as additional evidence.
            if profile != 'libvhdi':
                subprocess.run(['cp', '-R', assertion, str(directory / 'supply-protector')], check=True)
    scans = {'schema': 1, 'repository': 'closure-labs/xo-nixpkg', 'revision': revision,
             'producer': {'workflow': '.github/workflows/qualification.yml',
                          'runId': int(os.environ.get('GITHUB_RUN_ID', '0')),
                          'runAttempt': int(os.environ.get('GITHUB_RUN_ATTEMPT', '0'))},
             'scannedAt': started.isoformat(), 'expiresAt': (started + datetime.timedelta(hours=48)).isoformat(), 'profiles': profiles}
    scans['repositorySecretPolicy'] = native_binding()
    scans['productProducer'] = dict(scans['producer'], revision=revision)
    assets = {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in sorted(output.rglob('*')) if path.is_file() and path.name not in {'product.json', 'scans.json'} and not path.name.startswith('handoff-')}
    product = {'schema': 1, 'repository': 'closure-labs/xo-nixpkg', 'revision': revision,
               'products': products, 'assets': assets, 'roots': roots, 'repositorySecretPolicy': native_binding()}
    # Scan timestamps and databases change on rescan, so release product identity
    # contains only immutable inventory and closure assertions.
    product['assets'] = {name.replace('/', '--'): digest for name, digest in assets.items()
                         if name.endswith(('runtime.cdx.json', 'closure.json', 'derivations.json', 'inventory.json')) or '/supply-protector/' in name}
    for name, digest in product['assets'].items():
        source = output / name.replace('--', '/')
        (output / name).write_bytes(source.read_bytes())
    spec = importlib.util.spec_from_file_location('distribution_cache', os.environ['XO_NIXPKG_DISTRIBUTION_CACHE_SOURCE'])
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    all_roots = [*products.values(), *({'storePath': r['storePath'], 'narHash': r['narHash']} for r in roots.values())]
    scans['transport'] = transport.export(output, all_roots)
    (output / 'scans.json').write_text(json.dumps(scans, sort_keys=True, indent=2) + '\n')
    (output / 'product.json').write_text(json.dumps(product, sort_keys=True, indent=2) + '\n')
    for profile in products:
        handoff = {'schema': 1, 'repository': 'closure-labs/xo-nixpkg', 'revision': revision,
                   'channel': profile, 'product': product, 'scans': scans}
        (output / f'handoff-{profile}.json').write_text(json.dumps(handoff, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
