# SPDX-License-Identifier: Apache-2.0
"""Exact-head queue reconciliation and ambiguous acknowledgement recovery."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / 'ci/decisions' if (ROOT / 'ci').is_dir() else ROOT / 'nix/automation/decisions'
sys.path.insert(0, str(CORE))
import reconciliation as queue

CFG = {'repository': 'owner/repo'}
HEAD = 'a' * 40
PULL = {'state': 'open', 'merged': False, 'node_id': 'PR_fixture', 'head': {'sha': HEAD}}
STATE = {'id': 'PR_fixture', 'headRefOid': HEAD, 'state': 'OPEN', 'merged': False,
         'mergeStateStatus': 'CLEAN', 'autoMergeRequest': None, 'mergeQueueEntry': None}


class QueueStates(unittest.TestCase):
    def setUp(self):
        self.pull = copy.deepcopy(PULL)
        self.states = [copy.deepcopy(STATE)]
        self.calls = []
        self.mutation_error = None
        self.addCleanup(patch.stopall)
        patch.object(queue, 'required_check').start()
        patch.object(queue.authority, 'github_api', side_effect=lambda endpoint: self.pull).start()
        self.approve = patch.object(queue.authority, 'approval').start()
        patch.object(queue, 'command', side_effect=self.command).start()

    def command(self, args):
        self.calls.append(args)
        if args[1:3] == ['pr', 'merge']:
            self.states[0]['autoMergeRequest'] = {'enabledAt': 'now'}
            return ''
        if any('query=query' in arg for arg in args):
            value = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            return json.dumps({'data': {'node': value}})
        if self.mutation_error:
            raise self.mutation_error
        self.states[0]['mergeQueueEntry'] = {'id': 'QUEUE_fixture'}
        return json.dumps({'data': {'enqueuePullRequest': {'mergeQueueEntry': {'id': 'QUEUE_fixture'}}}})

    def mutations(self):
        return [args for args in self.calls if any('mutation(' in arg for arg in args) or args[1:3] == ['pr', 'merge']]

    def test_queued_merged_closed_and_changed_heads_do_not_mutate(self):
        for changes, expected in [({'mergeQueueEntry': {'id': 'Q'}}, 'queued'),
                                  ({'state': 'MERGED', 'merged': True}, 'merged'),
                                  ({'state': 'CLOSED'}, 'closed'),
                                  ({'headRefOid': 'b' * 40}, 'changed-head')]:
            self.states = [dict(STATE, **changes)]; self.calls.clear()
            self.assertEqual(queue.queue_proposal(CFG, 1), expected)
            self.assertEqual(self.mutations(), [])

    def test_waiting_review_and_checks_do_not_enqueue(self):
        self.approve.side_effect = queue.authority.HumanDecisionRequired('review missing')
        self.assertEqual(queue.queue_proposal(CFG, 1), 'awaiting-review')
        self.assertEqual(self.mutations(), [])
        self.approve.side_effect = None
        self.states[0]['mergeStateStatus'] = 'BLOCKED'
        self.assertEqual(queue.queue_proposal(CFG, 1), 'awaiting-checks')
        self.assertEqual(len(self.mutations()), 1)  # Enable protected auto-merge once.
        self.calls.clear()
        self.assertEqual(queue.queue_proposal(CFG, 1), 'awaiting-checks')
        self.assertEqual(self.mutations(), [])

    def test_ready_head_queues_once_with_fresh_approval(self):
        self.assertEqual(queue.queue_proposal(CFG, 1), 'queued')
        self.assertEqual(self.approve.call_count, 2)
        self.assertIn(HEAD, self.mutations()[0])
        self.assertIn('head=' + HEAD, self.mutations()[1])
        self.assertTrue(any('expectedHeadOid:$head' in arg for arg in self.mutations()[1]))
        self.calls.clear()
        self.assertEqual(queue.queue_proposal(CFG, 1), 'queued')
        self.assertEqual(self.mutations(), [])

    def test_ambiguous_enqueue_is_read_back_without_retry(self):
        self.mutation_error = subprocess.TimeoutExpired(['gh'], 30)
        self.states = [copy.deepcopy(STATE), copy.deepcopy(STATE),
                       dict(STATE, mergeQueueEntry={'id': 'Q'})]
        self.assertEqual(queue.queue_proposal(CFG, 1), 'queued')
        self.assertEqual(sum(any('mutation(' in arg for arg in args) for args in self.calls), 1)

    def test_unknown_enqueue_failure_remains_blocked(self):
        self.mutation_error = subprocess.CalledProcessError(1, ['gh'], stderr='untrusted raw response')
        with self.assertRaisesRegex(ValueError, 'Enqueue acknowledgement unavailable'):
            queue.queue_proposal(CFG, 1)

    def test_revoked_review_after_planning_blocks_enqueue(self):
        self.approve.side_effect = [None, queue.authority.HumanDecisionRequired('revoked')]
        with self.assertRaises(queue.authority.HumanDecisionRequired):
            queue.queue_proposal(CFG, 1)
        self.assertFalse(any(any('mutation(' in arg for arg in args) for args in self.calls))


if __name__ == '__main__':
    unittest.main()
