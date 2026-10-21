# SPDX-License-Identifier: Apache-2.0
"""Required materialization preserves raw signed bytes and rejects workspace links."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
CORE=Path(__file__).resolve().parents[2]
CORE=CORE/'ci/decisions' if (CORE/'ci').exists() else CORE/'nix/automation/decisions'
sys.path.insert(0,str(CORE))
import decision_packets as packets

class Recovery(unittest.TestCase):
    def test_atomic_install_rejects_prior_links_and_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';source.write_bytes(b'original\n  signed bytes\n')
            directory=root/'out';directory.mkdir();output=directory/'asset'
            packets.install_member(source,output,directory)
            self.assertEqual(output.read_bytes(),source.read_bytes())
            output.unlink();output.symlink_to(root/'missing')
            with self.assertRaises(ValueError):packets.install_member(source,output,directory)
            self.assertFalse((root/'missing').exists())
            output.unlink();(directory/'nested').symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError):packets.install_member(source,directory/'nested/escaped',directory)
            self.assertFalse((root/'escaped').exists())

    def test_copy_checks_remaining_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';source.write_bytes(b'bytes');output=root/'output'
            with patch.object(packets.operations,'remaining',side_effect=ValueError('expired')):
                with self.assertRaisesRegex(ValueError,'expired'):packets.install_member(source,output,root)
            self.assertFalse(output.exists());self.assertEqual(sorted(x.name for x in root.iterdir()),['source'])

if __name__=='__main__':unittest.main()
