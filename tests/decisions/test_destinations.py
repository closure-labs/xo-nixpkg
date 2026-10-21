# SPDX-License-Identifier: Apache-2.0
import base64
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
CORE=Path(__file__).resolve().parents[2]
CORE=CORE/'ci/decisions' if (CORE/'ci').exists() else CORE/'nix/automation/decisions'
sys.path.insert(0,str(CORE))
import destinations as d
P='/nix/store/'+'0'*32+'-fixture'
H='sha256-'+base64.b64encode(bytes(32)).decode()
PRODUCT={'products':{'fixture':{'storePath':P,'narHash':H}},'revision':'a'*40}
BODY=f'StorePath: {P}\nNarHash: sha256:{"0"*52}\nNarSize: 1\n'.encode()

class Destinations(unittest.TestCase):
    def test_cache_missing_partial_verified_conflict_unavailable(self):
        for code,body,state in [(404,b'','missing'),(200,BODY,'verified'),(503,b'','unavailable'),
                                (200,BODY.replace(b'NarSize: 1',b'NarSize: 0'),'conflict')]:
            with self.subTest(state=state):
                value=d.cache(PRODUCT,'https://maestro.cachix.org',lambda _: (code,body))
                self.assertEqual(value['status'],state)
                if state!='verified':
                    with self.assertRaises(ValueError):d.receipt(value,PRODUCT)
        value=d.cache(PRODUCT,'https://maestro.cachix.org',lambda _: (200,BODY))
        self.assertEqual(d.receipt(value,PRODUCT)['expected'],{P:H})

    def test_nix_base32_preserves_byte_order_and_high_bits(self):
        raw=bytes(range(32));number=int.from_bytes(raw,'little')
        encoded=''.join(d.ALPHABET[(number>>(5*i))&31] for i in reversed(range(52)))
        self.assertEqual(d.nar_hash('sha256:'+encoded),'sha256-'+base64.b64encode(raw).decode())
        with self.assertRaises(ValueError):d.nar_hash('sha256:'+'z'*52)

    def test_flakehub_verifies_exact_pinned_revision_without_source_download(self):
        location='https://api.flakehub.com/f/pinned/closure-labs/maestro/3.0.0/uuid/source.tar.gz'
        calls=[]
        def read(url,head):
            calls.append((url,head))
            return 307,((f'Location: {location}\r\n' if len(calls)==1 else
                        f'Link: <{location}?rev={PRODUCT["revision"]}&revCount=1>; rel="immutable"\r\n').encode())
        self.assertEqual(d.flakehub('3.0.0',PRODUCT['revision'],read)['status'],'verified')
        self.assertTrue(all(head for _,head in calls));self.assertEqual(len(calls),2)
        self.assertEqual(d.flakehub('3.0.0',PRODUCT['revision'],lambda *a,**k:(404,b''))['status'],'missing')
        self.assertEqual(d.flakehub('3.0.0',PRODUCT['revision'],lambda *a,**k:(503,b''))['status'],'unavailable')

if __name__=='__main__':unittest.main()
