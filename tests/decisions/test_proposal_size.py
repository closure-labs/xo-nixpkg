"""Proposal producers cannot publish bytes the live authority reader rejects."""
import json
import re
from pathlib import Path
import sys
import tomllib
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci/decisions'))
import reconciliation as mod
from test_authority import PROPOSAL, REPO, BOT


class ProposalSize(unittest.TestCase):
    def test_readable_document_preserves_identity_and_respects_exact_limit(self):
        content = mod.proposal_content(PROPOSAL)
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
        with patch.object(mod.authority, 'MAX_PROPOSAL_BYTES', len(content.encode())), \
             patch.object(mod.authority, 'github_api', side_effect=api), \
             patch.object(mod, 'api_write', side_effect=write), \
             patch.object(mod, 'queue_proposal', return_value='waiting'):
            result = mod.propose(cfg, PROPOSAL)
        entry = writes[0][1]['tree'][0]
        self.assertEqual(entry['content'], content)
        self.assertEqual(json.loads(content), PROPOSAL)
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
    def test_preserves_key_policy_lines_and_every_json_value(self):
        proposal = {'payload': {'profiles': {'xo-latest': [
            {'key': 'a' * 64, 'severity': 'high',
             'note': '  leading spaces\nnew line\t\"quote\" \u2603'},
            {'key': 'b' * 64, 'severity': 'low'}]}},
                    'numbers': [None, True, False, 1, -2, 1.5]}
        content = mod.proposal_content(proposal)
        pretty = json.dumps(proposal, sort_keys=True, indent=2, allow_nan=False) + '\n'
        config = tomllib.loads((Path(__file__).resolve().parents[2] / '.gitleaks.toml').read_text())
        rule = next(rule for rule in config['rules'] if rule['id'] == 'generic-api-key')
        policy = re.compile(rule['allowlists'][0]['regexes'][0])
        self.assertEqual([line for line in content.splitlines() if policy.fullmatch(line)],
                         [line for line in pretty.splitlines() if policy.fullmatch(line)])
        self.assertEqual(len([line for line in content.splitlines() if policy.fullmatch(line)]), 2)
        self.assertEqual(json.loads(content), proposal)
        self.assertEqual(mod.canonical_hash(json.loads(content)), mod.canonical_hash(proposal))
        self.assertLess(len(content), len(pretty))
        self.assertLess(max(map(len, content.splitlines())), 150)

    def test_nonfinite_values_still_rejected(self):
        for value in (float('nan'), float('inf'), -float('inf')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mod.proposal_content({'value': value})

    def test_one_byte_over_limit_fails_before_any_remote_access_or_write(self):
        content = mod.proposal_content(PROPOSAL)
        with patch.object(mod.authority, 'MAX_PROPOSAL_BYTES', len(content.encode()) - 1), \
             patch.object(mod.authority, 'github_api') as read, \
             patch.object(mod, 'api_write') as write, \
             self.assertRaisesRegex(ValueError, 'bounded Git blob limit'):
            mod.propose({'repository': REPO, 'botLogin': BOT}, PROPOSAL)
        read.assert_not_called()
        write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
