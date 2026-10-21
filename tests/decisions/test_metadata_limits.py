# SPDX-License-Identifier: Apache-2.0
"""Large native observations remain bounded, authenticated metadata reads."""
import json
import subprocess
import time
from pathlib import Path
import unittest
from unittest import mock
from test_packets import Registry, mod, sha


class NativeScanMetadata(unittest.TestCase):
    def registry(self, name, data=b'{}', size=None):
        registry=Registry()
        record={'size':len(data) if size is None else size,'sha256':sha(data)}
        registry.packet={'schema':1,'producer':{'runId':7,'runAttempt':1},'files':{name:record}}
        registry.packet_bytes=json.dumps(registry.packet).encode()
        registry.layers[:]=[registry.layer('decision-packet.json',registry.packet_bytes),
                           {'annotations':{'org.opencontainers.image.title':name},
                            'digest':'sha256:'+record['sha256'],'size':record['size']}]
        registry.blobs={sha(registry.packet_bytes):registry.packet_bytes,sha(data):data}
        registry.refresh()
        return registry

    def test_real_native_scan_size_reads_only_descriptor_and_requested_document(self):
        # Measured from the retained producer39630152023 artifact ZIP directory.
        prefix,suffix=b'{"padding":"',b'"}'
        data=prefix+b'x'*(64335207-len(prefix)-len(suffix))+suffix
        registry=self.registry('scans.json',data)
        with mock.patch.object(mod,'command',side_effect=registry.command) as command:
            result=mod.metadata_bytes(registry.reference,mod.canonical_hash(registry.packet),
                                      'scans.json',producer=registry.packet['producer'])
        self.assertEqual(sha(result),sha(data))
        self.assertEqual(command.call_count,3)
        self.assertEqual(command.call_args.kwargs['max_file_bytes'],len(data))

    def test_scan_cap_and_generic_metadata_cap_reject_before_blob_transfer(self):
        for name,size in [('scans.json',128*1024**2+1),('product.json',16*1024**2+1),
                          ('nested/scans.json',16*1024**2+1),('closure.tar',16*1024**2+1)]:
            with self.subTest(name=name):
                registry=self.registry(name,size=size)
                with mock.patch.object(mod,'command',side_effect=registry.command) as command:
                    with self.assertRaisesRegex(ValueError,'oversized'):
                        mod.metadata_bytes(registry.reference,mod.canonical_hash(registry.packet),name)
                self.assertEqual(command.call_count,1)

    def test_integrity_failure_and_typed_producer_mismatch_block(self):
        registry=self.registry('scans.json',b'{"native":true}')
        def corrupted(args,**kwargs):
            if args[1:3]==['blob','fetch'] and args[3].endswith(sha(b'{"native":true}')):
                Path(args[args.index('--output')+1]).write_bytes(b'corrupt')
                return b''
            return registry.command(args,**kwargs)
        with mock.patch.object(mod,'command',side_effect=corrupted):
            with self.assertRaisesRegex(ValueError,'integrity'):
                mod.metadata_bytes(registry.reference,mod.canonical_hash(registry.packet),'scans.json')
        for producer in [{'runId':8,'runAttempt':1},{'runId':7,'runAttempt':True}]:
            with mock.patch.object(mod,'command',side_effect=registry.command) as command:
                with self.assertRaisesRegex(ValueError,'producer differs'):
                    mod.metadata_bytes(registry.reference,mod.canonical_hash(registry.packet),
                                       'scans.json',producer=producer)
            self.assertEqual(command.call_count,2)

    def test_larger_scan_does_not_extend_the_existing_metadata_deadline(self):
        registry=self.registry('scans.json')
        with mod.operations.budget(.001):
            time.sleep(.005)
            with self.assertRaises(subprocess.TimeoutExpired):
                mod.metadata_bytes(registry.reference,mod.canonical_hash(registry.packet),'scans.json')


if __name__=='__main__':unittest.main()
