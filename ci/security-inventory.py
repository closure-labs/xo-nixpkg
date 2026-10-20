#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inventory installed npm packages and exact versioned native closure outputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import quote


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def native_files(root):
    result = []
    paths = [root] if root.is_file() else (Path(d) / f for d, _, files in os.walk(root) for f in files)
    for path in paths:
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as handle:
            if handle.read(4) == b'\x7fELF':
                result.append(str(path))
    return sorted(result)


def npm_components(root):
    components = []
    manifests = sorted(root.rglob('package.json'))
    for manifest in manifests:
        if manifest.is_symlink():
            continue
        relative = manifest.relative_to(root)
        parts = relative.parts
        if 'node_modules' in parts:
            tail = parts[len(parts) - 1 - parts[::-1].index('node_modules') + 1:]
            if not ((len(tail) == 2 and not tail[0].startswith('@')) or
                    (len(tail) == 3 and tail[0].startswith('@'))):
                continue
        elif not (len(parts) == 3 and parts[0] in {'packages', '@xen-orchestra', '@vates'}):
            continue
        data = json.loads(manifest.read_text())
        name, version = data.get('name'), data.get('version')
        # Fixture/package metadata with no package identity is not installed code.
        if not name and not version:
            continue
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise ValueError(f'incomplete installed npm identity: {manifest}')
        purl = f'pkg:npm/{quote(name, safe="/")}@{quote(version, safe="")}'
        components.append({'type': 'library', 'name': name, 'version': version,
                           'purl': purl, 'bom-ref': 'npm:' + str(manifest),
                           'properties': [{'name': 'xo-nixpkg:manifestPath', 'value': str(manifest)},
                               *({'name': 'xo-nixpkg:installedPath', 'value': str(path)}
                                 for path in sorted(manifest.parent.rglob('*'))
                                 if path.is_file() and not path.is_symlink()
                                 and 'node_modules' not in path.relative_to(manifest.parent).parts)]})
    if not components:
        raise ValueError('no installed npm packages found')
    return components


def exact_output(record, output, info):
    path = info.get('path')
    if path and not path.startswith('/'):
        path = '/nix/store/' + path
    declared = record.get('env', {}).get(output)
    if path and declared and path != declared:
        raise ValueError('inconsistent exact derivation output paths')
    return path or declared


def inventory(root, closure, derivations, xo=True):
    components = npm_components(root / 'libexec/xen-orchestra') if xo else []
    for path in sorted(closure):
        shipped = native_files(Path(path))
        if not shipped:
            continue
        candidates = []
        for drv_path, record in derivations.items():
            env = record.get('env', {})
            structured = record.get('structuredAttrs', json.loads(env.get('__json', '{}')))
            attrs = {**env, **structured}
            if any(exact_output(record, output, info) == path for output, info in record.get('outputs', {}).items()):
                candidates.append((drv_path, attrs, [output for output, info in record['outputs'].items() if exact_output(record, output, info) == path][0]))
        if len(candidates) != 1:
            raise ValueError(f'no unambiguous exact native derivation for {path}')
        drv, attrs, output_name = candidates[0]
        if not drv.startswith('/'):
            drv = '/nix/store/' + drv
        name, version = attrs.get('pname'), attrs.get('version')
        if not name or not version:
            raise ValueError(f'unversioned shipped native code: {path}')
        components.append({'type': 'library', 'name': name, 'version': version,
                           'purl': f'pkg:nix/{quote(name, safe="")}@{quote(version, safe="")}',
                           'bom-ref': path, 'properties': [
                               {'name': 'nix:storePath', 'value': path},
                               {'name': 'nix:derivation', 'value': drv},
                               {'name': 'xo-nixpkg:outputName', 'value': output_name},
                               *({'name': 'xo-nixpkg:installedPath', 'value': file} for file in shipped)]})
    if not components:
        raise ValueError('empty runtime inventory')
    for component in components:
        if component['purl'].startswith('pkg:npm/'):
            root_producer = [(record, output) for record in derivations.values()
                             for output, info in record.get('outputs', {}).items()
                             if exact_output(record, output, info) == str(root)]
            if len(root_producer) != 1:
                raise ValueError('ambiguous installed npm output producer')
            component['properties'] += [{'name': 'nix:storePath', 'value': str(root)},
                                        {'name': 'xo-nixpkg:outputName', 'value': root_producer[0][1]}]
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
            'components': components,
            'properties': [{'name': 'xo:coverage', 'value': 'installed-npm-and-native-closure'}]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--profile', required=True, choices=['xo-latest', 'xo-stable', 'xo-rolling', 'libvhdi'])
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--additional-root', action='append', default=[])
    args = parser.parse_args()
    closure = json.loads(command('nix', 'path-info', '--recursive', '--json', str(args.root), *args.additional_root))
    if isinstance(closure, list):
        closure = {record['path']: record for record in closure}
    closure = {path: {key: info[key] for key in ('narHash', 'references') if key in info}
               for path, info in closure.items()}
    drvs = sorted(set(command('nix-store', '--query', '--deriver', *closure).splitlines()))
    if any(not drv.endswith('.drv') for drv in drvs):
        raise ValueError('closure derivation metadata is missing')
    records = {}
    for start in range(0, len(drvs), 64):
        batch = json.loads(command('nix', 'derivation', 'show', *drvs[start:start + 64]))
        records.update(batch.get('derivations', batch))
    args.output.mkdir(parents=True, exist_ok=True)
    sbom = inventory(args.root, closure, records, args.profile != 'libvhdi')
    for name, value in [('runtime.cdx.json', sbom), ('closure.json', closure), ('derivations.json', records)]:
        (args.output / name).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    manifest = {name: hashlib.sha256((args.output / name).read_bytes()).hexdigest()
                for name in ('runtime.cdx.json', 'closure.json', 'derivations.json')}
    (args.output / 'inventory.json').write_text(json.dumps({'schemaVersion': 1, 'profile': args.profile,
        'root': str(args.root), 'coverage': 'complete', 'documents': manifest}, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
