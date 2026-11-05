# SPDX-License-Identifier: Apache-2.0
"""Offline guards only: never fetch evidence or invoke a real Nix command."""
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('capacity_probe', ROOT / 'ci/validate-restore-capacity.py')
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


class Guards(unittest.TestCase):
    def test_fixed_identity_and_nonpublishing_bounds(self):
        self.assertEqual((M.RUN, M.ATTEMPT), (41955054111, 1))
        self.assertEqual(M.RESERVE, 2 * 1024 ** 3)
        for value in (M.SOURCE, M.REVISION): self.assertRegex(value, r'^[0-9a-f]{40}$')
        for value in (M.RESTORE_SHA256, M.PACKET, M.PRODUCT): self.assertRegex(value, r'^[0-9a-f]{64}$')

    def test_aggregate_caps_are_required(self):
        M.validate_caps(str(4 * M.GiB), '0', '200000 100000')
        for memory, swap, cpu in [('max','0','200000 100000'), (str(8*M.GiB),'0','200000 100000'),
                                  (str(4*M.GiB),'max','200000 100000'), (str(4*M.GiB),'1','200000 100000'),
                                  (str(4*M.GiB),'0','max 100000'), (str(4*M.GiB),'0','300000 100000')]:
            with self.subTest(memory=memory, swap=swap, cpu=cpu), self.assertRaises(M.Blocked):
                M.validate_caps(memory, swap, cpu)

    def test_packet_sizes_are_strict_and_bounded(self):
        self.assertEqual(M.packet_bounds({'product.json':{'size':10}}), 10)
        bad = [{}, {'x':{'size':True}}, {'x':{'size':0}}, {'scans.json':{'size':129*1024**2}},
               {'distribution-cache.tar.part-000':{'size':1_800_000_001}}]
        bad.append({f'distribution-cache.tar.part-{n:03d}':{'size':1_800_000_000} for n in range(3)})
        for members in bad:
            with self.subTest(members=members), self.assertRaises(M.Blocked): M.packet_bounds(members)

    def test_narinfo_cannot_request_remote_or_escaping_payload(self):
        class Transport:
            STORE = re.compile(r'/nix/store/[a-z0-9]{32}-[^/\s]+')
            @staticmethod
            def safe_name(name):
                if not name or ':' in name or name.startswith('/') or any(x in ('','.','..') for x in name.split('/')):
                    raise ValueError('unsafe')
                return name
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary); (cache/'nar').mkdir(); (cache/'nar/file.zst').write_bytes(b'data')
            base='StorePath: /nix/store/'+'a'*32+'-root\nNarSize: 100\nURL: nar/file.zst\n'
            self.assertEqual(M.narinfo(base.encode(),cache,Transport)[1],100)
            for value in [base+'NarSize: 101\n',base.replace('100','0'),base.replace('100','-1'),
                          base.replace('nar/file.zst','https://private.invalid/key'),
                          base.replace('nar/file.zst','../escape'),base.replace('nar/file.zst','nar/missing')]:
                with self.subTest(value=value), self.assertRaises((M.Blocked,ValueError)):
                    M.narinfo(value.encode(),cache,Transport)

    def test_errors_never_publish_arbitrary_exception_text(self):
        self.assertEqual(M.safe_error(ValueError('PRIVATE_TOKEN /private/path')), 'diagnostic-failed')
        self.assertEqual(M.safe_error(ValueError('HTTP 403 PRIVATE_TOKEN')), 'read-http-403')
        self.assertEqual(M.safe_error(M.Blocked('source-revision')), 'source-revision')

    def test_workflow_is_single_event_read_only_and_has_no_secrets(self):
        text=(ROOT/'.github/workflows/restore-capacity.yml').read_text()
        self.assertIn('types: [opened]', text)
        self.assertNotIn('pull_request_target', text)
        self.assertNotIn('workflow_dispatch', text)
        self.assertNotIn('secrets.', text)
        self.assertNotRegex(text, r'\b(?:contents|packages|actions|attestations|id-token):\s*write')
        for required in ('MemoryMax=4G','MemorySwapMax=0','CPUQuota=200%','NIX_REMOTE=local','persist-credentials: false'):
            self.assertIn(required,text)
        self.assertIn('ref: '+M.SOURCE,text)

    def test_probe_does_not_call_publication_leaves(self):
        text=(ROOT/'ci/validate-restore-capacity.py').read_text()
        for forbidden in ("command(['cachix'", "command(['git', 'push'", "packets.push(", "remote_handoff(", "Journal(", "publication-gate"):
            self.assertNotIn(forbidden,text)
        self.assertIn("os.environ.pop(name, None)",text)
        self.assertIn("transport.validate_manifest(evidence, native['transport'])",text)

    def test_classifier_maps_all_new_execution_paths_without_publication(self):
        cfg=json.loads((ROOT/'ci/classifier.json').read_text())
        for path in ('ci/validate-restore-capacity.py','tests/test_restore_capacity.py','.github/workflows/restore-capacity.yml'):
            rule=next(r for r in cfg['pathRules'] if re.search(r['pattern'],path))
            self.assertEqual(rule['validation'], ['*']);self.assertEqual(rule['publication'], [])


if __name__ == '__main__': unittest.main()
