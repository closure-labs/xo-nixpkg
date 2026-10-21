#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extend advisory coverage with authenticated inputs; retain all legacy coverage."""
import hashlib
import json
from pathlib import Path
import sys


def union(original,additional):
    result=json.loads(json.dumps(original))
    baseline=result.get('components',[])
    if not baseline or not isinstance(additional.get('components'),list):raise ValueError('Incomplete advisory inventory')
    refs={item.get('bom-ref') for item in baseline}
    additions=[]
    for item in additional['components']:
        if not isinstance(item.get('bom-ref'),str) or not item.get('purl') or not item.get('version'):
            raise ValueError('Shared inventory lacks complete component identity')
        item=json.loads(json.dumps(item));item['bom-ref']='shared-native:'+item['bom-ref']
        if item['bom-ref'] in refs:raise ValueError('Shared inventory component reference collision')
        item.setdefault('properties',[]).append({'name':'xo-nixpkg:sharedNative','value':'true'})
        refs.add(item['bom-ref']);additions.append(item)
    result['components']+=additions
    # Preserve the original dependency graph byte-for-byte as data; extra native
    # exposure lives in component properties and does not replace any baseline.
    return result


def main():
    inventory,shared,channel=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
    manifest=json.loads((shared/'shared-inventories.json').read_text())
    record=manifest['channels'][channel];path=shared/record['file']
    if path.parent!=shared or path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=record['sha256']:
        raise ValueError('Shared advisory inventory bytes differ from authenticated product')
    value=union(json.loads(inventory.read_text()),json.loads(path.read_text()))
    inventory.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


if __name__=='__main__':main()
