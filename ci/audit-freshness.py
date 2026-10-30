#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh protected-main native posture/alert observation at EVERY publication boundary.

No audit-run or saved-receipt fallback. Product vulnerability/authority checks
remain in publication-gate.sh after this independent live prerequisite.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

path = os.environ.get('XO_NATIVE_SECRET_CONTROLLER_SOURCE', str(Path(__file__).with_name('native-secret-controller.py')))
spec = importlib.util.spec_from_file_location('native_publication_observer', path)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def verify(controller, product, scans, api, now=None, metadata_api=None):
    native.sha(controller)
    native.require(isinstance(product, dict) and product.get('repository') == native.REPO, 'product-schema')
    revision = native.sha(product.get('revision'))
    native.validate_product_policy(product, scans)
    return native.observe(api, controller, {'sha': revision, 'kind': 'product', 'run': None},
                          metadata_api=metadata_api, **({'now': now} if now is not None else {}))


def main():
    native.require(os.environ.get('GITHUB_REPOSITORY') == native.REPO
                   and os.environ.get('GITHUB_REF') == 'refs/heads/main', 'controller-context')
    controller = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    directory = Path(os.environ['XO_NIXPKG_EVIDENCE'])
    values = []
    for name in ('product.json', 'scans.json'):
        p = directory / name
        native.require(p.is_file() and not p.is_symlink() and p.stat().st_size <= 16 * 1024 * 1024, 'evidence-file')
        values.append(native.decode(p.read_bytes()))
    receipt = verify(controller, *values, native.API(os.environ.get('NATIVE_SECRET_OBSERVER_TOKEN')),
                     metadata_api=native.MetadataAPI(os.environ.get('GH_TOKEN')))
    print(json.dumps({'status': 'observed', 'policyId': receipt['policyId'],
                      'fullHistoryCompletionClaim': False, 'openAlertCount': 0}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Publication blocked: fresh native secret observation and new-policy qualification required', file=sys.stderr)
        raise SystemExit(1)
