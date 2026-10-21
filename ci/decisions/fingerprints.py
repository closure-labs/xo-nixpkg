# SPDX-License-Identifier: Apache-2.0
"""Independent dependency keys; diagnostics and raw-byte reuse, never admission."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import observability


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=False,allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_identity(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file():raise ValueError('Fingerprint input must be a regular file')
    with path.open('rb') as stream:
        return {'sha256':hashlib.file_digest(stream,'sha256').hexdigest(),'size':path.stat().st_size}


def bindings(raw,normalization,runtime,observations,attestation):
    raw_key=digest(raw)
    normalized=digest({'rawInventory':raw_key,'normalizationInputs':normalization})
    context=digest(runtime)
    observed=digest({'normalizedInventory':normalized,'runtimeContext':context,'observationInputs':observations})
    return {'schema':1,'authorityClaim':False,'rawInventory':raw_key,'normalization':normalized,
            'runtimeContext':context,'observations':observed,
            'attestations':digest({'observations':observed,'attestationInputs':attestation})}


def raw_inventory(inputs,generate):
    """Job- and exact-tree-scoped reuse of bytes, with revalidation on every hit."""
    started=time.monotonic()
    scope={key:os.environ.get(key) for key in ('GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB')}
    temporary=os.environ.get('RUNNER_TEMP')
    if not temporary or not all(scope.values()):
        raw=generate()
        observability.stage('inventory-generation',started,cache='miss')
        return raw
    scope['verifier']=file_identity(Path(__file__))['sha256']
    parent=Path(temporary)/'inventory-cache'/digest(scope)
    target=parent/digest(inputs)
    for directory in (Path(temporary),Path(temporary)/'inventory-cache',parent):
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise ValueError('Unsafe inventory cache parent')
    if target.is_symlink():raise ValueError('Inventory cache link forbidden')
    if target.exists():
        receipt=target/'receipt.json';payload=target/'inventory.json'
        if target.is_symlink() or not target.is_dir() or receipt.is_symlink() or not receipt.is_file():
            raise ValueError('Unsafe inventory cache entry')
        if {p.name for p in target.iterdir()} != {'receipt.json','inventory.json'}:raise ValueError('Unexpected inventory cache members')
        record=json.loads(receipt.read_bytes())
        if (not isinstance(record,dict) or set(record)!={'schema','inputs','inventory'} or type(record['schema']) is not int or record['schema']!=1
                or canonical(record.get('inputs'))!=canonical(inputs) or canonical(record.get('inventory'))!=canonical(file_identity(payload))):
            raise ValueError('Inventory cache differs from exact inputs or bytes')
        raw=payload.read_bytes()
        observability.stage('inventory-generation',started,cache='hit')
        return raw
    parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as pending:
        pending=Path(pending);payload=pending/'inventory.json'
        raw=generate()
        if not isinstance(raw,bytes) or not raw:raise ValueError('Empty inventory generation')
        payload.write_bytes(raw)
        (pending/'receipt.json').write_bytes(canonical({'schema':1,'inputs':inputs,'inventory':file_identity(payload)}))
        pending.rename(target)
        observability.stage('inventory-generation',started,cache='miss')
        return raw
