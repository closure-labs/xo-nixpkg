# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[2]
CORE=ROOT/'ci/decisions' if (ROOT/'ci').is_dir() else ROOT/'nix/automation/decisions'
sys.path.insert(0,str(CORE))
import fingerprints as f

class Fingerprints(unittest.TestCase):
    def test_dependency_layers_invalidate_only_affected_bindings(self):
        args=[{'inventory':'bytes','generator':'v1'},{'normalizer':'v1'},{'policy':'v1'},{'db':'v1','observedAt':'now'},{'producer':'run1'}]
        baseline=f.bindings(*args)
        for index,changed in enumerate([{'generator':'v2'},{'normalizer':'v2'},{'policy':'v2'},{'db':'v2'},{'producer':'run2'}]):
            values=list(args);values[index]=changed;actual=f.bindings(*values)
            changed_keys={key for key in baseline if baseline[key]!=actual[key]}
            self.assertEqual(changed_keys,[{'rawInventory','normalization','observations','attestations'},
                {'normalization','observations','attestations'},{'runtimeContext','observations','attestations'},
                {'observations','attestations'},{'attestations'}][index])

    def test_existing_cache_cannot_be_reached_through_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            env=dict(RUNNER_TEMP=tmp,GITHUB_REPOSITORY='fixture/repo',GITHUB_SHA='a'*40,GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1',GITHUB_JOB='scan')
            with patch.dict(os.environ,env):
                f.raw_inventory({'generator':'v1'},lambda:b'original')
                root=Path(tmp);(root/'inventory-cache').rename(root/'moved-cache')
                (root/'inventory-cache').symlink_to(root/'moved-cache',target_is_directory=True)
                with self.assertRaises(ValueError):f.raw_inventory({'generator':'v1'},lambda:b'changed')

    def test_raw_reuse_requires_exact_tree_inputs_and_unchanged_regular_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            env=dict(RUNNER_TEMP=tmp,GITHUB_REPOSITORY='fixture/repo',GITHUB_SHA='a'*40,GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1',GITHUB_JOB='scan')
            generate=Mock(return_value=b'{"original":"bytes"}\n')
            with patch.dict(os.environ,env):
                inputs={'rootNarHash':'approved','generator':'v1'}
                self.assertEqual(f.raw_inventory(inputs,generate),f.raw_inventory(inputs,generate))
                self.assertEqual(generate.call_count,1)
                cached_payload=next(Path(tmp).rglob('inventory.json'))
                with patch.dict(os.environ,GITHUB_SHA='b'*40):f.raw_inventory(inputs,generate)
                self.assertEqual(generate.call_count,2)
                f.raw_inventory(dict(inputs,generator='v2'),generate)
                self.assertEqual(generate.call_count,3)
                cached_payload.write_bytes(b'corrupt')
                with self.assertRaises(ValueError):f.raw_inventory(inputs,generate)
                self.assertEqual(generate.call_count,3)

if __name__=='__main__':unittest.main()
