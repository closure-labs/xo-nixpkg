# SPDX-License-Identifier: Apache-2.0
"""Deploy compatible journal readers before enabling new destination receipts."""
import copy
from pathlib import Path
import sys
import unittest

CORE = Path(__file__).resolve().parents[2]
CORE = CORE / 'ci/decisions' if (CORE / 'ci').is_dir() else CORE / 'nix/automation/decisions'
sys.path.insert(0, str(CORE))
import publication_receipts as receipts

HASH = 'a'*64
RECEIPT = {'schema':1, 'productHash':HASH, 'destination':'cache', 'status':'verified',
           'expected':{'roots':{'fixture':'sha256-approved'}}, 'observed':{'roots':{'fixture':'sha256-approved'}},
           'verifiedAt':'2026-01-01T00:00:00Z', 'verifier':'b'*64}


class Readers(unittest.TestCase):
    def test_legacy_completion_remains_readable_without_remote_proof(self):
        self.assertEqual(receipts.read({'schema':1,'productHash':HASH,'steps':{'cache':'complete'}},HASH),{})

    def test_identity_comparison_preserves_json_types(self):
        for value in (True, 1.0):
            bad=copy.deepcopy(RECEIPT)
            bad['expected']={'runId':1}
            bad['observed']={'runId':value}
            with self.assertRaises(ValueError):
                receipts.validate(bad,HASH,'cache')

    def test_new_verified_receipt_is_bound_to_product_and_destination(self):
        document={'schema':2,'productHash':HASH,'steps':{'cache':'complete'},'receipts':{'cache':RECEIPT}}
        self.assertEqual(receipts.read(document,HASH),{'cache':RECEIPT})
        for field, value in [('schema',True),('productHash','c'*64),('status','partial'),
                             ('observed',{'roots':{'fixture':'different'}}),('destination','handoff'),
                             ('verifier','unknown'),('verifiedAt','2026-01-01')]:
            with self.subTest(field=field):
                bad=copy.deepcopy(document);bad['receipts']['cache'][field]=value
                with self.assertRaises(ValueError):
                    receipts.read(bad,HASH)
        with self.assertRaises(ValueError):
            receipts.read(dict(document,schema=1),HASH)


if __name__ == '__main__':
    unittest.main()
