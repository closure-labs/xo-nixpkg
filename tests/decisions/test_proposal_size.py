"""Proposal producers cannot publish bytes the live authority reader rejects."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci/decisions'))
import reconciliation as mod
from test_authority import PROPOSAL, REPO, BOT


class ProposalSize(unittest.TestCase):
    def test_compact_document_preserves_identity_and_respects_exact_limit(self):
        compact = json.dumps(PROPOSAL, sort_keys=True, separators=(',', ':')) + '\n'
        cfg = {'repository': REPO, 'botLogin': BOT}
        writes = []
        def write(endpoint, body):
            writes.append((endpoint, body))
            if endpoint.endswith('/pulls'):
                return {'number': 7, 'user': {'login': BOT, 'type': 'Bot'}}
            return {'sha': 'c' * 40}
        def api(endpoint):
            if '/pulls?' in endpoint:
                return []
            if '/git/ref/' in endpoint:
                return {'object': {'sha': 'a' * 40}}
            return {'tree': {'sha': 'b' * 40}}
        with patch.object(mod.authority, 'MAX_PROPOSAL_BYTES', len(compact.encode())), \
             patch.object(mod.authority, 'github_api', side_effect=api), \
             patch.object(mod, 'api_write', side_effect=write), \
             patch.object(mod, 'queue_proposal', return_value='waiting'):
            result = mod.propose(cfg, PROPOSAL)
        entry = writes[0][1]['tree'][0]
        self.assertEqual(entry['content'], compact)
        self.assertEqual(json.loads(compact), PROPOSAL)
        self.assertEqual(result['proposalHash'], mod.canonical_hash(PROPOSAL))
        self.assertEqual(entry['path'], mod.authority.proposal_path(PROPOSAL))

    def test_closed_or_merged_proposal_is_diagnosed_before_remote_writes(self):
        for merged in (False, True):
            with self.subTest(merged=merged), \
                    patch.object(mod.authority, 'collection', return_value=[{
                        'number': 176, 'state': 'closed', 'merged': merged}]) as read, \
                    patch.object(mod, 'api_write') as write, \
                    patch.object(mod, 'queue_proposal') as queue:
                with self.assertRaisesRegex(ValueError, 'refusing to reopen or overwrite'):
                    mod.propose({'repository': REPO, 'botLogin': BOT}, PROPOSAL)
                self.assertIn('state=all', read.call_args.args[1])
                write.assert_not_called()
                queue.assert_not_called()

    def test_one_byte_over_limit_fails_before_any_remote_access_or_write(self):
        compact = json.dumps(PROPOSAL, sort_keys=True, separators=(',', ':')) + '\n'
        with patch.object(mod.authority, 'MAX_PROPOSAL_BYTES', len(compact.encode()) - 1), \
             patch.object(mod.authority, 'github_api') as read, \
             patch.object(mod, 'api_write') as write, \
             self.assertRaisesRegex(ValueError, 'bounded Git blob limit'):
            mod.propose({'repository': REPO, 'botLogin': BOT}, PROPOSAL)
        read.assert_not_called()
        write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
