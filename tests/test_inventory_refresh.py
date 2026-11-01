"""Small mocked transport fixtures; no Nix, scanner, network or real credentials."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ci/decisions'))

def module(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),ROOT/'ci'/f'{name}.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def fixture(directory):
    inventory={'components':[{'purl':'pkg:nix/fixture@1','properties':[
        {'name':'nix:storePath','value':'/nix/store/root'},
        {'name':'xo-nixpkg:outputName','value':'out'},
        {'name':'xo-nixpkg:installedPath','value':'/nix/store/root/bin/fixture'}]}]}
    raw=json.dumps(inventory).encode();asset='xo-latest--runtime.cdx.json'
    (directory/asset).write_bytes(raw)
    prod={'schema':1,'repository':'closure-labs/xo-nixpkg','revision':'a'*40,
          'repositorySecretPolicy':module('refresh-products').native_binding(),
          'products':{'xo-latest':{'storePath':'/nix/store/root','narHash':'sha256-fixture'}},
          'assets':{asset:hashlib.sha256(raw).hexdigest()}}
    scan={'transport':{'parts':{'distribution-cache.tar.part-000':{'sha256':'c'*64,'size':9}}},
          'producer':{'workflow':'.github/workflows/qualification.yml','revision':'a'*40,'runId':1,'runAttempt':1},
          'productProducer':{'workflow':'.github/workflows/qualification.yml','revision':'a'*40,'runId':1,'runAttempt':1}}
    (directory/'product.json').write_text(json.dumps(prod));(directory/'scans.json').write_text(json.dumps(scan))
    return prod,scan,raw

class InventoryVerifierTests(unittest.TestCase):
    def run_verify(self, mutate=None, crypto_error=False):
        m=module('verify-rescan-evidence')
        with tempfile.TemporaryDirectory() as t:
            directory=Path(t);prod,scan,raw=fixture(directory)
            if mutate:mutate(directory,prod)
            with patch.dict(os.environ,{'XO_NIXPKG_EVIDENCE':str(directory),'XO_NIXPKG_FETCH_FULL_TRANSPORT':'false'}), \
                 patch.object(m,'config',return_value={}), \
                 patch.object(m,'scans',return_value=scan,side_effect=ValueError('crypto') if crypto_error else None), \
                 patch.object(m,'product',return_value=prod):
                m.main()
    def test_complete_inventory_passes_without_closure_parts(self):self.run_verify()
    def test_missing_tampered_and_extra_inventory_fail(self):
        mutations=[lambda d,p:(d/'xo-latest--runtime.cdx.json').unlink(),
                   lambda d,p:(d/'xo-latest--runtime.cdx.json').write_bytes(b'changed'),
                   lambda d,p:(d/'distribution-cache.tar.part-000').write_bytes(b'unwanted')]
        for change in mutations:
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_verify(change)
    def test_symlinks_fail(self):
        def change(d,p):
            f=d/'xo-latest--runtime.cdx.json';f.unlink();f.symlink_to(d/'product.json')
        with self.assertRaises(ValueError):self.run_verify(change)
    def test_crypto_failure_remains_terminal(self):
        with self.assertRaisesRegex(ValueError,'crypto'):self.run_verify(crypto_error=True)

class RefreshTests(unittest.TestCase):
    def run_refresh(self, mutate=None):
        m=module('refresh-products');normalizer=module('security-normalize')
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);source=root/'input';source.mkdir();output=root/'output';prod,scan,raw=fixture(source)
            if mutate:mutate(source,prod)
            report={'matches':[{'artifact':{'purl':'pkg:nix/fixture@1'},'vulnerability':{'id':'CVE-fixture','severity':'High'}}]}
            expected=normalizer.normalize(json.loads(raw),report)['observations']
            commands=[];scans=[]
            def command(*args):
                commands.append(args)
                if args[:2]==('xo-nixpkg-security-database','prepare'):return 'd'*64
                if args[0]=='git':return 'b'*40
                raise AssertionError('Unexpected command, including Nix realization')
            def run(args,**kwargs):
                self.assertEqual(args[0],'xo-nixpkg-security-native-scan')
                self.assertNotIn('GH_TOKEN',os.environ)
                self.assertEqual(Path(args[1],'runtime.cdx.json').read_bytes(),raw)
                self.assertEqual(args[-1],'d'*64);scans.append(args)
                result=normalizer.normalize(json.loads(raw),copy.deepcopy(report))
                Path(args[2],'scan.json').write_text(json.dumps(result))
            with patch.dict(os.environ,{'XO_NIXPKG_RESCAN_SOURCE':str(source),'XO_NIXPKG_EVIDENCE':str(output),
                 'GITHUB_RUN_ID':'2','GITHUB_RUN_ATTEMPT':'1','GH_TOKEN':'synthetic-must-be-removed'}), \
                 patch.object(m,'command',side_effect=command),patch.object(m.subprocess,'run',side_effect=run):
                m.main()
            self.assertEqual((output/'product.json').read_bytes(),(source/'product.json').read_bytes())
            result=json.loads((output/'scans.json').read_text())
            self.assertEqual(result['profiles']['xo-latest']['observations'],expected)
            self.assertEqual(result['transport'],scan['transport']);self.assertEqual(result['productProducer'],scan['productProducer'])
            self.assertEqual(len(scans),1);self.assertEqual(sum(c[0]=='xo-nixpkg-security-database' for c in commands),1)
            self.assertFalse(list(output.glob('distribution-cache.tar.part-*')))
    def test_same_sbom_and_mocked_fresh_report_produce_same_real_normalized_findings(self):self.run_refresh()
    def test_absent_and_tampered_sbom_fail_before_scanning(self):
        for change in [lambda d,p:(d/'xo-latest--runtime.cdx.json').unlink(),lambda d,p:(d/'xo-latest--runtime.cdx.json').write_bytes(b'bad')]:
            with self.subTest(change=change),self.assertRaises(ValueError):self.run_refresh(change)

class RetainedInventoryTests(unittest.TestCase):
    def fetch(self, change=None):
        m=module('fetch-retained');packets=m.packets
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);seed=root/'seed';seed.mkdir();prod,scan,raw=fixture(seed)
            blobs={p.name:p.read_bytes() for p in seed.iterdir()}
            blobs['distribution-cache.tar.part-000']=b'closure must never be fetched'
            producer={'repository':'closure-labs/xo-nixpkg','revision':'a'*40,'sourceRevision':'a'*40,
                      'workflow':'.github/workflows/qualification.yml','runId':1,'runAttempt':1}
            files={n:{'sha256':hashlib.sha256(v).hexdigest(),'size':len(v)} for n,v in blobs.items()}
            descriptor={'schema':1,'producer':producer,'files':files}
            if change=='missing':descriptor['files'].pop('xo-latest--runtime.cdx.json');blobs.pop('xo-latest--runtime.cdx.json')
            if change=='producer':descriptor['producer']=dict(producer,runAttempt=2)
            blobs['decision-packet.json']=json.dumps(descriptor).encode()
            members=dict(descriptor['files'],**{'decision-packet.json':{'sha256':hashlib.sha256(blobs['decision-packet.json']).hexdigest(),'size':len(blobs['decision-packet.json'])}})
            if change=='tampered':blobs['xo-latest--runtime.cdx.json']=b'tampered'
            packet={'reference':packets.REGISTRY+'@sha256:'+'e'*64,'sha256':packets.canonical_hash(descriptor),'producer':producer}
            read=[]
            def command(args,**kwargs):
                self.assertEqual(args[:3],['oras','blob','fetch'])
                digest=args[3].rsplit('@sha256:',1)[1]
                name=next(n for n,r in members.items() if r['sha256']==digest)
                read.append(name);self.assertNotEqual(name,'distribution-cache.tar.part-000')
                Path(args[-1]).write_bytes(blobs[name]);return b''
            with patch.object(packets,'inspect',return_value=(b'fixture',members)),patch.object(packets,'command',side_effect=command):
                out=root/'output';m.inventory_only(packet,out)
            self.assertEqual(set(p.name for p in out.iterdir()),{'product.json','scans.json',*prod['assets']})
            self.assertEqual((out/'xo-latest--runtime.cdx.json').read_bytes(),raw)
            self.assertNotIn('distribution-cache.tar.part-000',read)
    def test_real_packet_member_hashing_materializes_only_listed_inventory(self):self.fetch()
    def test_missing_tampered_or_wrong_producer_fail_closed(self):
        for change in ('missing','tampered','producer'):
            with self.subTest(change=change),self.assertRaises(ValueError):self.fetch(change)

class FetchWiringTests(unittest.TestCase):
    def fetch(self, mode='normal', full=False):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t);binary=d/'bin';binary.mkdir();log=d/'calls';output=d/'output'
            gh=binary/'gh'
            gh.write_text('#!'+sys.executable+'\n'+r"""
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with Path(os.environ['FIXTURE_LOG']).open('a') as f:f.write(json.dumps(['gh',*args])+'\n')
mode=os.environ['FIXTURE_MODE']
if args[0]=='api':
 if '/artifacts?' in args[1]:
  if mode=='api-denied':sys.exit(1)
  rows=[{'name':'qualified-inventories-1-1','expired':False,'size_in_bytes':128}]
  if mode=='missing':rows=[]
  if mode=='duplicate':rows*=2
  if mode=='oversized':rows[0]['size_in_bytes']=536870913
  if mode=='malformed':rows[0].pop('expired')
  print(json.dumps({'total_count':len(rows)+(1 if mode=='incomplete' else 0),'artifacts':rows}))
 else:print(json.dumps({'conclusion':'success','head_repository':{'full_name':'closure-labs/xo-nixpkg'},'head_branch':'main','event':'push','path':'.github/workflows/qualification.yml','run_attempt':1}))
elif args[:2]==['run','download']:
 if mode=='download-failed':sys.exit(1)
 name=args[args.index('--name')+1]
 expected='qualified-products-1-1' if os.environ.get('XO_NIXPKG_FETCH_FULL_TRANSPORT')=='true' else 'qualified-inventories-1-1'
 assert name==expected
 target=Path(args[args.index('--dir')+1]);target.mkdir();(target/'scans.json').write_text(json.dumps({'producer':{'runId':1,'runAttempt':1}}))
else:sys.exit(90)
""")
            gh.chmod(0o755)
            oras=binary/'oras';oras.write_text('#!'+sys.executable+'\nimport sys\nsys.stdin.read() if "--password-stdin" in sys.argv else None\n');oras.chmod(0o755)
            retained=d/'retained.py';retained.write_text("import os,json\nfrom pathlib import Path\np=Path(os.environ['XO_NIXPKG_EVIDENCE']);p.mkdir();(p/'scans.json').write_text(json.dumps({'producer':{'runId':1,'runAttempt':1}}));(p/'mode').write_text(os.environ.get('XO_NIXPKG_RESCAN_INVENTORY_ONLY','false'))\n")
            verify=d/'verify.py';verify.write_text("import os\nfrom pathlib import Path\n(Path(os.environ['XO_NIXPKG_EVIDENCE'])/'verified').write_text('yes')\n")
            env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],FIXTURE_LOG=str(log),FIXTURE_MODE=mode,
                QUALIFICATION_RUN='1',QUALIFICATION_ATTEMPT='1',GITHUB_REPOSITORY='closure-labs/xo-nixpkg',GITHUB_ACTOR='fixture',
                XO_NIXPKG_FETCH_BOUNDED='true',XO_NIXPKG_FETCH_FOR_RESCAN='true',XO_NIXPKG_FETCH_FULL_TRANSPORT=str(full).lower(),
                XO_NIXPKG_PUBLICATION_METADATA_ONLY='false',XO_NIXPKG_EVIDENCE=str(output),REGISTRY_TOKEN='synthetic',
                XO_NIXPKG_OPERATIONS_SOURCE=str(ROOT/'ci/decisions/operations.py'),XO_NIXPKG_RETAINED_FETCH_SOURCE=str(retained),XO_NIXPKG_RESCAN_VERIFIER_SOURCE=str(verify))
            result=subprocess.run(['bash',str(ROOT/'ci/fetch-evidence.sh')],env=env,capture_output=True,text=True,timeout=15)
            calls=[json.loads(line) for line in log.read_text().splitlines()]
            return result.returncode,calls,(output/'verified').exists(),(output/'mode').read_text() if (output/'mode').exists() else None
    def test_native_refresh_downloads_only_inventory_and_verifies(self):
        code,calls,verified,_=self.fetch();self.assertEqual(code,0);self.assertTrue(verified)
        downloads=[c for c in calls if c[1:3]==['run','download']]
        self.assertEqual(len(downloads),1);self.assertIn('qualified-inventories-1-1',downloads[0])
    def test_api_denial_duplicate_incomplete_oversized_or_failed_download_never_falls_back(self):
        for mode in ('api-denied','duplicate','incomplete','oversized','malformed','download-failed'):
            with self.subTest(mode=mode):
                code,calls,verified,fallback=self.fetch(mode)
                self.assertNotEqual(code,0);self.assertFalse(verified);self.assertIsNone(fallback)
                self.assertFalse(any('qualified-products-1-1' in c for c in calls))
    def test_absence_uses_inventory_only_retained_reader(self):
        code,calls,verified,fallback=self.fetch('missing');self.assertEqual(code,0);self.assertTrue(verified)
        self.assertEqual(fallback,'true');self.assertFalse(any(c[1:3]==['run','download'] for c in calls))
    def test_actual_publication_can_explicitly_fetch_original_full_transport(self):
        code,calls,verified,_=self.fetch(full=True);self.assertEqual(code,0);self.assertTrue(verified)
        self.assertTrue(any('qualified-products-1-1' in c for c in calls));self.assertFalse(any('/artifacts?' in ' '.join(c) for c in calls))

class LazyRestoreTests(unittest.TestCase):
    def invoke(self, altered=None):
        m=module('restore-products')
        with tempfile.TemporaryDirectory() as t:
            d=Path(t);prod,scan,_=fixture(d);transport=d/'transport.py'
            transport.write_text('def restore(*args): pass\n');restored=[];fetched=[]
            class Transport:
                def validate_manifest(self,*args):return list(scan['transport']['parts'])
                def restore(self,*args):restored.append(args)
            original_loader=m.importlib.util.module_from_spec
            def loader(spec):
                return Transport() if spec.name=='distribution_cache' else original_loader(spec)
            original_spec=m.importlib.util.spec_from_file_location
            def spec(name,path):
                if name=='distribution_cache':return SimpleNamespace(name=name,loader=SimpleNamespace(exec_module=lambda _:None))
                return original_spec(name,path)
            def run(args,**kw):
                if args==['xo-nixpkg-publication-gate']:return
                self.assertEqual(args,['xo-nixpkg-fetch-evidence']);env=kw['env'];fetched.append(env)
                self.assertEqual(env['QUALIFICATION_RUN'],'1');self.assertEqual(env['QUALIFICATION_ATTEMPT'],'1')
                self.assertEqual(env['XO_NIXPKG_FETCH_FULL_TRANSPORT'],'true')
                dest=Path(env['XO_NIXPKG_EVIDENCE']);dest.mkdir()
                (dest/'product.json').write_bytes((d/'product.json').read_bytes());out=copy.deepcopy(scan)
                if altered=='product':(dest/'product.json').write_text('{}')
                if altered=='transport':out['transport']={'different':True}
                (dest/'scans.json').write_text(json.dumps(out))
                (dest/'distribution-cache.tar.part-000').write_bytes(b'fixture')
            with patch.dict(os.environ,{'XO_NIXPKG_EVIDENCE':str(d),'XO_NIXPKG_DISTRIBUTION_CACHE_SOURCE':str(transport)}), \
                 patch.object(sys,'argv',['restore-products']), \
                 patch.object(m.subprocess,'run',side_effect=run), \
                 patch.object(m.importlib.util,'spec_from_file_location',side_effect=spec), \
                 patch.object(m.importlib.util,'module_from_spec',side_effect=loader):m.main()
            self.assertEqual(len(fetched),1);self.assertEqual(len(restored),1)
    def test_absent_parts_fetch_original_authenticated_producer_once(self):self.invoke()
    def test_wrong_product_or_transport_never_restores(self):
        for which in ('product','transport'):
            with self.subTest(which=which),self.assertRaises(ValueError):self.invoke(which)

if __name__=='__main__':unittest.main()
