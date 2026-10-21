# SPDX-License-Identifier: Apache-2.0
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ci/decisions'))

class AdvisoryInputs(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('advisory_input_fixture',ROOT/'ci/advisory-inputs.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name)
        self.revision='a'*40
        self.producer={'workflow':'.github/workflows/qualification.yml','runId':1,'runAttempt':2,
                       'repository':'closure-labs/xo-nixpkg','revision':self.revision,'sourceRevision':self.revision}
        native_producer={k:v for k,v in self.producer.items() if k not in ('repository','sourceRevision')}
        self.native={'revision':self.revision,'producer':native_producer}
        self.raw=b'{"components": []}\n';digest=hashlib.sha256(self.raw).hexdigest()
        self.product={'revision':self.revision,'assets':{'xo-'+c+'--runtime.cdx.json':digest for c in ('latest','stable','rolling')}}
        self.packet={'reference':'fixture-reference','sha256':'b'*64,'producer':self.producer}
        self.retained=self.work/'retained.py'
        self.run={'id':1,'run_attempt':2,'status':'completed','head_sha':self.revision,'head_branch':'main',
                  'head_repository':{'full_name':'closure-labs/xo-nixpkg'},'path':'.github/workflows/qualification.yml',
                  'event':'push','conclusion':'success'}

    def invoke(self,corrupt=False,attestation_failure=False):
        self.retained=self.work/('retained-'+str(len(list(self.work.glob('retained-*.py'))))+'.py')
        self.retained.write_text('def find_packets(*args):return '+repr([self.packet])+'\n')
        output=self.work/'out';output.mkdir(exist_ok=True)
        calls=[]
        def metadata(reference,digest,name,producer):
            calls.append(name)
            if name in ('scans.json','product.json'):return b'{"original": "signed bytes"}\n'
            return b'corrupt' if corrupt else self.raw
        with patch.dict(os.environ,XO_NIXPKG_RETAINED_FETCH_SOURCE=str(self.retained)), \
             patch.object(sys,'argv',['advisory-inputs',str(output)]), \
             patch.object(self.module.operations,'run',return_value=subprocess.CompletedProcess([],0,stdout=self.revision,stderr='')), \
             patch.object(self.module.common,'config',return_value={'repository':'closure-labs/xo-nixpkg'}), \
             patch.object(self.module.authority,'github_api',return_value={'workflow_runs':[self.run]}), \
             patch.object(self.module.packets,'metadata_bytes',side_effect=metadata), \
             patch.object(self.module,'inventory_bytes',side_effect=metadata), \
             patch.object(self.module.common,'scans',return_value=self.native,side_effect=ValueError('invalid attestation') if attestation_failure else None), \
             patch.object(self.module.common,'product',return_value=self.product):
            self.module.main()
        return output,calls

    def test_signed_exact_source_inventory_is_read_without_payload(self):
        output,calls=self.invoke()
        self.assertEqual(calls,['scans.json','product.json','xo-latest--runtime.cdx.json','xo-stable--runtime.cdx.json','xo-rolling--runtime.cdx.json'])
        self.assertEqual((output/'scans.json').read_bytes(),b'{"original": "signed bytes"}\n')
        self.assertEqual(set(json.loads((output/'shared-inventories.json').read_text())['channels']),{'latest','stable','rolling'})

    def test_invalid_attestation_hash_and_producer_block_instead_of_fallback(self):
        with self.assertRaises(ValueError):self.invoke(corrupt=True)
        with self.assertRaises(ValueError):self.invoke(attestation_failure=True)
        self.producer['runAttempt']=3
        with self.assertRaises(ValueError):self.invoke()

    def test_historical_product_is_ineligible_without_weakening_provenance(self):
        self.product['revision']='b'*40
        with self.assertRaises(SystemExit) as error:self.invoke()
        self.assertEqual(error.exception.code,4)
        self.assertFalse((self.work/'out/shared-inventories.json').exists())

    def test_real_packet_inventory_over_metadata_limit_is_verified_without_closure_fetch(self):
        sys.path.insert(0,str(ROOT/'tests/decisions'))
        from test_packets import Registry
        registry=Registry();packets=self.module.packets
        name='xo-latest--runtime.cdx.json'
        raw=b'{"components": []}\n'+b' '*(17*1024**2)
        payload_hash=hashlib.sha256(raw).hexdigest()
        registry.packet={'schema':1,'producer':self.producer,'files':{name:{'size':len(raw),'sha256':payload_hash}}}
        registry.packet_bytes=json.dumps(registry.packet).encode()
        registry.layers=[registry.layer('decision-packet.json',registry.packet_bytes),registry.layer(name,raw)]
        registry.manifest['layers']=registry.layers
        registry.blobs={hashlib.sha256(registry.packet_bytes).hexdigest():registry.packet_bytes,payload_hash:raw};registry.refresh()
        expected=packets.canonical_hash(registry.packet)
        with patch.object(packets,'command',side_effect=registry.command) as command:
            with self.assertRaises(ValueError):packets.metadata_bytes(registry.reference,expected,name)
            self.assertEqual(self.module.inventory_bytes(registry.reference,expected,name,self.producer),raw)
            self.assertEqual([call.args[0][1:3] for call in command.call_args_list],
                             [['manifest','fetch'],['manifest','fetch'],['blob','fetch'],['blob','fetch']])
            command.reset_mock()
            with self.assertRaises(ValueError):
                self.module.inventory_bytes(registry.reference,expected,name,dict(self.producer,runAttempt=99))
            self.assertEqual(command.call_count,2)  # Reject producer before the large inventory.
            with self.assertRaises(ValueError):
                self.module.inventory_bytes(registry.reference,expected,name,dict(self.producer,runId=True))
            registry.blobs[payload_hash]=b'x'*len(raw)
            with self.assertRaises(ValueError):self.module.inventory_bytes(registry.reference,expected,name,self.producer)

    def test_inventory_reader_rejects_closure_names_and_oversized_inventories(self):
        packets=self.module.packets
        with patch.object(packets,'inspect') as inspect:
            with self.assertRaises(ValueError):self.module.inventory_bytes('reference','digest','distribution-cache.tar.part-000',self.producer)
            inspect.assert_not_called()
            inspect.return_value=(b'',{'xo-stable--runtime.cdx.json':{'size':64*1024**2+1}})
            with self.assertRaises(ValueError):self.module.inventory_bytes('reference','digest','xo-stable--runtime.cdx.json',self.producer)

if __name__=='__main__':unittest.main()
