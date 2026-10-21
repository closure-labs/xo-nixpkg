# SPDX-License-Identifier: Apache-2.0
"""Bounded, read-only destination identity reconciliation. Never grants authority."""
import argparse
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlparse, parse_qs, quote
import operations

ALPHABET='0123456789abcdfghijklmnpqrsvwxyz'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def nar_hash(value):
    if re.fullmatch(r'sha256-[A-Za-z0-9+/]{43}=', value):
        raw=base64.b64decode(value[7:], validate=True)
    elif re.fullmatch(r'sha256:['+ALPHABET+r']{52}', value):
        number=sum(ALPHABET.index(c) << (5*i) for i,c in enumerate(reversed(value[7:])))
        if number >= 1 << 256:
            raise ValueError('Invalid NAR hash')
        raw=number.to_bytes(32,'little')
    else:
        raise ValueError('Invalid NAR hash')
    return 'sha256-'+base64.b64encode(raw).decode()


def http(url, head=False):
    # Only caller-constructed, credential-free public endpoints are accepted.
    parsed=urlparse(url)
    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Invalid public destination URL')
    with tempfile.TemporaryDirectory(prefix='destination-read-') as temp:
        body=Path(temp)/'body'
        args=['curl','--silent','--show-error','--proto','=https','--max-time','30',
              '--max-filesize',str(2*1024*1024),'--user-agent','Nix/2.34',
              '--output',str(body),'--write-out','%{http_code}']
        if head:
            args+=['--head']
        result=operations.run([*args,url], capture_output=True, text=True, timeout=30, check=False)
        if result.returncode or not re.fullmatch(r'[0-9]{3}',result.stdout):
            return None,b''
        data=body.read_bytes() if body.exists() else b''
        if len(data)>2*1024*1024:
            return None,b''
        return int(result.stdout),data


def result(destination, expected, observed, missing=(), unavailable=False):
    conflict=any(key in observed and canonical(observed[key]) != canonical(value) for key,value in expected.items())
    state=('conflict' if conflict else 'unavailable' if unavailable else
           'verified' if not missing else 'partial' if observed else 'missing')
    return {'schema':1,'destination':destination,'status':state,'expected':expected,
            'observed':observed,'missing':sorted(missing),'authorityClaim':False}


def cache(product, url, read=http):
    if url not in ('https://maestro.cachix.org','https://xen-orchestra-ce.cachix.org'):
        raise ValueError('Unknown public cache')
    expected={}
    for entry in [*product['products'].values(),*product.get('roots',{}).values()]:
        path=entry['storePath']
        if not re.fullmatch(r'/nix/store/['+ALPHABET+r']{32}-[^/\s]+',path):
            raise ValueError('Invalid approved store path')
        digest=nar_hash(entry['narHash'])
        if path in expected and expected[path] != digest:
            raise ValueError('Conflicting approved root identities')
        expected[path]=digest
    if not expected:
        raise ValueError('Empty cache inventory')
    observed={}; missing=[]; unavailable=False
    with operations.budget(120):
        for path in sorted(expected):
            try:
                status,body=read(url+'/'+Path(path).name[:32]+'.narinfo')
            except subprocess.TimeoutExpired:
                status,body=None,b''
            if status==404:
                missing.append(path)
            elif status==200:
                fields={}
                for line in body.decode('utf-8').splitlines():
                    key,sep,value=line.partition(': ')
                    if not sep or (key in fields and key != 'Sig'):
                        raise ValueError('Malformed public cache metadata')
                    fields[key]=value
                if fields.get('StorePath') != path or not re.fullmatch(r'[1-9][0-9]*',fields.get('NarSize','')):
                    observed[path]='invalid-metadata'
                else:
                    observed[path]=nar_hash(fields.get('NarHash',''))
            else:
                unavailable=True
    return result('cache',expected,observed,missing,unavailable)


def flakehub(version, revision, read=http):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:\+rev-[0-9a-f]{40})?',version) or not re.fullmatch(r'[0-9a-f]{40}',revision):
        raise ValueError('Invalid immutable FlakeHub identity')
    expected={'version':version,'revision':revision}; observed={}
    status,body=read('https://api.flakehub.com/f/closure-labs/maestro/'+quote('='+version,safe=''),head=True)
    if status==404:
        return result('flakehub',expected,observed,expected)
    if status != 307:
        return result('flakehub',expected,observed,unavailable=True)
    headers=body.decode().splitlines()
    locations=[line.split(':',1)[1].strip() for line in headers if line.lower().startswith('location:')]
    if len(locations)!=1:
        raise ValueError('Invalid FlakeHub immutable location')
    location=urlparse(locations[0]); segments=location.path.split('/')
    if location.scheme!='https' or location.netloc!='api.flakehub.com' or segments[:5]!=['','f','pinned','closure-labs','maestro'] or len(segments)!=8 or segments[-1]!='source.tar.gz':
        raise ValueError('Unexpected FlakeHub immutable identity')
    observed['version']=segments[5]
    status,body=read(locations[0],head=True)
    if status!=307:
        return result('flakehub',expected,observed,unavailable=True)
    links=[line.split(':',1)[1].strip() for line in body.decode().splitlines() if line.lower().startswith('link:')]
    if len(links)!=1:
        raise ValueError('Missing FlakeHub revision proof')
    match=re.fullmatch(r'<([^>]+)>; rel="immutable"',links[0])
    if not match:
        raise ValueError('Invalid FlakeHub revision proof')
    proof=urlparse(match[1]); values=parse_qs(proof.query)
    if proof.scheme!='https' or proof.netloc!=location.netloc or proof.path!=location.path or len(values.get('rev',[]))!=1:
        raise ValueError('FlakeHub immutable source differs')
    observed['revision']=values['rev'][0]
    return result('flakehub',expected,observed)


def receipt(value, product):
    if value['status']!='verified' or canonical(value['expected'])!=canonical(value['observed']):
        raise ValueError('Destination has no current verification proof')
    return {'schema':1,'destination':value['destination'],'productHash':hashlib.sha256(canonical(product)).hexdigest(),
            'status':'verified','expected':value['expected'],'observed':value['observed'],
            'verifiedAt':dt.datetime.now(dt.timezone.utc).isoformat(),'verifier':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination',choices=['cache','flakehub'])
    parser.add_argument('--product',required=True,type=Path)
    parser.add_argument('--cache-url')
    parser.add_argument('--version')
    parser.add_argument('--require-verified',action='store_true')
    parser.add_argument('--receipt',type=Path)
    args=parser.parse_args(); product=json.loads(args.product.read_text())
    value=cache(product,args.cache_url) if args.destination=='cache' else flakehub(args.version,product['revision'])
    print(json.dumps(value,sort_keys=True))
    if value['status'] in ('conflict','unavailable') or (args.require_verified and value['status']!='verified'):
        raise SystemExit('Public destination '+value['status'])
    if args.receipt and value['status']=='verified':
        args.receipt.write_bytes(canonical(receipt(value,product))+b'\n')


if __name__=='__main__':
    main()
