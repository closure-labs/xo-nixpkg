"""Decider commands are authenticated exact-head Comment reviews only."""
import copy
import unittest
from test_authority import GitHub, HEAD, REPO, mod


class CommentReviewAuthority(unittest.TestCase):
    def review(self, api, command=None):
        api.reviews[0].update(state='COMMENTED', body=command or '/decider approve ' + HEAD)
        return api.reviews[0]

    def authorize(self, api):
        return mod.approval(api, REPO, 7, HEAD)

    def test_explicit_exact_head_comment_review(self):
        api = GitHub()
        self.review(api)
        self.assertEqual(self.authorize(api)['approvalMethod'], 'comment-review')

    def test_unrelated_or_wrong_head_command_never_authorizes(self):
        for body in ('approved', '/decider approve', '/decider approve ' + 'b' * 40,
                     'please /decider approve ' + HEAD, '/decider approve ' + HEAD + '\nextra'):
            api = GitHub()
            self.review(api, body)
            with self.subTest(body=body), self.assertRaises(mod.HumanDecisionRequired):
                self.authorize(api)
        api = GitHub()
        self.review(api)['commit_id'] = 'b' * 40
        with self.assertRaises(mod.HumanDecisionRequired):
            self.authorize(api)

    def test_current_human_eligibility_is_required(self):
        for change in ('bot', 'permission', 'membership'):
            api = GitHub()
            self.review(api)
            if change == 'bot':
                api.reviews[0]['user']['type'] = 'Bot'
            elif change == 'permission':
                api.roles['maintainer'] = 'write'
            else:
                api.memberships['maintainer'] = {'state': 'pending', 'role': 'member'}
            with self.subTest(change=change), self.assertRaises(mod.HumanDecisionRequired):
                self.authorize(api)

    def test_latest_withdrawal_changes_request_or_dismissal_revokes(self):
        for state, body in [('COMMENTED', '/decider withdraw ' + HEAD),
                            ('CHANGES_REQUESTED', ''), ('DISMISSED', '')]:
            api = GitHub()
            original = self.review(api)
            api.reviews.append({**copy.deepcopy(original), 'id': 11, 'state': state, 'body': body})
            with self.subTest(state=state), self.assertRaises(mod.HumanDecisionRequired):
                self.authorize(api)

    def test_later_command_can_replace_own_withdrawal_but_not_another_veto(self):
        api = GitHub()
        first = self.review(api, '/decider withdraw ' + HEAD)
        api.reviews.append({**copy.deepcopy(first), 'id': 11, 'body': '/decider approve ' + HEAD})
        self.assertEqual(self.authorize(api)['id'], 11)
        api.roles['other'] = 'maintain'
        api.reviews.append({'id': 12, 'state': 'CHANGES_REQUESTED', 'commit_id': HEAD,
                            'user': {'id': 2, 'login': 'other', 'type': 'User'}})
        with self.assertRaises(mod.HumanDecisionRequired):
            self.authorize(api)

    def test_edited_command_is_read_again_without_cached_authority(self):
        api = GitHub()
        review = self.review(api)
        self.authorize(api)
        review['body'] = '/decider withdraw ' + HEAD
        with self.assertRaises(mod.HumanDecisionRequired):
            self.authorize(api)
        review['body'] = 'ordinary comment'
        with self.assertRaises(mod.HumanDecisionRequired):
            self.authorize(api)

    def test_malformed_body_fails_closed(self):
        for body in (False, 0, [], {}):
            api = GitHub()
            self.review(api)['body'] = body
            with self.subTest(body=body), self.assertRaises(mod.AuthorityError):
                self.authorize(api)


if __name__ == '__main__':
    unittest.main()
