#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Optional exact-source signed inventories; observations and decisions are never reused."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import common
import decision_authority as authority
import decision_packets as packets
import operations


def inventory_bytes(reference, expected, name, producer):
    """Materialize only an authenticated runtime inventory, never closure data."""
    if name not in {'xo-'+channel+'--runtime.cdx.json' for channel in ('latest','stable','rolling')}:
        raise ValueError('Unsupported shared inventory member')
    with operations.budget(180), tempfile.TemporaryDirectory(prefix='advisory-inventory-') as temporary:
        directory=Path(temporary)
        _,members=packets.inspect(reference)
        if name not in members or members[name]['size']>64*1024**2:
            raise ValueError('Shared inventory is absent or exceeds 64 MiB')
        descriptor=packets.packet_descriptor(packets.fetch_member('decision-packet.json',directory,members),members,expected)
        if packets.canonical_hash(descriptor['producer'])!=packets.canonical_hash(producer):
            raise ValueError('Shared inventory producer differs from authenticated packet')
        return packets.fetch_member(name,directory,members).read_bytes()


def main():
    with operations.budget(300):
        output=Path(sys.argv[1])
        with operations.budget(90):
            revision=operations.run(['git','rev-parse','HEAD'],capture_output=True,text=True,check=True,timeout=30).stdout.strip()
            cfg=common.config(Path('ci/decision-policy.json'),live=True)
            runs=authority.github_api(f'repos/{cfg["repository"]}/actions/workflows/qualification.yml/runs?status=success&head_sha={revision}&per_page=20')['workflow_runs']
            runs=[r for r in runs if r.get('head_sha')==revision and r.get('head_branch')=='main'
                  and r.get('status')=='completed' and r.get('head_repository',{}).get('full_name')==cfg['repository'] and r.get('conclusion')=='success'
                  and r.get('path')=='.github/workflows/qualification.yml' and r.get('event') in ('push','schedule','workflow_dispatch')]
            if not runs:raise SystemExit(4)
            spec=importlib.util.spec_from_file_location('retained',os.environ['XO_NIXPKG_RETAINED_FETCH_SOURCE'])
            retained=importlib.util.module_from_spec(spec);spec.loader.exec_module(retained)
            found=retained.find_packets(cfg,runs[0]['id'],runs[0]['run_attempt'])
            if not found:raise SystemExit(4)
            if len(found)!=1:raise ValueError('Ambiguous exact-source advisory inventory packets')
        packet=found[0]
        for name in ('scans.json','product.json'):
            (output/name).write_bytes(packets.metadata_bytes(packet['reference'],packet['sha256'],name,producer=packet['producer']))
        native=common.scans(output/'scans.json',cfg,allow_expired=True)
        product=common.product(output/'product.json',cfg,native)
        producer=dict(native['producer'],repository=cfg['repository'],revision=native['producer'].get('revision',native['revision']),sourceRevision=native['revision'])
        if product['revision']!=revision:raise SystemExit(4)
        if (producer!=packet['producer'] or producer['revision']!=revision or producer['runId']!=runs[0]['id'] or producer['runAttempt']!=runs[0]['run_attempt']):
            raise ValueError('Shared inventory producer differs from exact selected source/run/attempt')
        channels={}
        for channel in ('latest','stable','rolling'):
            name='xo-'+channel+'--runtime.cdx.json'
            raw=inventory_bytes(packet['reference'],packet['sha256'],name,producer)
            expected=product['assets'].get(name)
            if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('Shared inventory differs from signed exact product')
            (output/name).write_bytes(raw);channels[channel]={'file':name,'sha256':expected}
        (output/'shared-inventories.json').write_text(json.dumps({'schema':1,'sourceRevision':revision,'producer':producer,'productHash':common.canonical_hash(product),'channels':channels},sort_keys=True)+'\n')


if __name__=='__main__':
    previous=os.environ.get('DOCKER_CONFIG')
    try:
        with operations.budget(300), tempfile.TemporaryDirectory(prefix='advisory-registry-') as temporary:
            os.environ['DOCKER_CONFIG']=temporary
            operations.run(['oras','login','ghcr.io','--username',os.environ['GITHUB_ACTOR'],'--password-stdin'],
                           input=os.environ['REGISTRY_TOKEN'],text=True,capture_output=True,check=True,timeout=30)
            main()
    finally:
        if previous is None:os.environ.pop('DOCKER_CONFIG',None)
        else:os.environ['DOCKER_CONFIG']=previous
