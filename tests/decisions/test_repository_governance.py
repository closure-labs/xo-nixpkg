# SPDX-License-Identifier: Apache-2.0
"""Staged repository governance: legacy default, live new approvals, durable old risk."""
import copy
import re
import unittest
from unittest.mock import patch
import common
from test_authority import GitHub, verify, mod, HEAD, MERGE, MAIN, REPO

SELECTED = 'repository-admin-or-super-admin'
MODE = {'mode':'repository-admin-or-super-admin-v1',
        'pastRiskAcceptances':'confirmed-merged-provenance','confirmedLegacyAcceptances':[]}


class RepositoryAPI(GitHub):
    def __call__(self, path):
        value = super().__call__(path)
        if '/collaborators/' in path:
            login=path.split('/collaborators/')[1].split('/')[0]
            value['user']={'id':1 if login=='maintainer' else 2,'login':login,'type':'User'}
        return value


class RepositoryGovernance(unittest.TestCase):
    def test_sole_maintainer_can_approve_bot_proposal_without_org_membership(self):
        api=RepositoryAPI();api.members=[];api.roles['maintainer']='admin'
        result=verify(api,reviewer_policy=SELECTED)
        self.assertEqual(result['status'],'authorized')
        self.assertEqual(result['permissionPolicy'],'current-repository-admin-or-super-admin')
        self.assertIsNone(result['approverTeam'])
        self.assertFalse(any(x.startswith('orgs/') for x in api.calls))

    def test_loss_of_access_blocks_a_new_approval(self):
        for role in ('read','triage','none','write'):
            api=RepositoryAPI();api.members=[];api.roles['maintainer']=role
            with self.subTest(role=role), self.assertRaises(mod.HumanDecisionRequired):
                verify(api,reviewer_policy=SELECTED)

    def test_active_super_admin_does_not_need_repository_write(self):
        for role in ('none','read','write','maintain'):
            api=RepositoryAPI();api.roles['maintainer']=role
            self.assertEqual(verify(api,reviewer_policy=SELECTED)['status'],'authorized')

    def test_pending_or_removed_super_admin_cannot_issue_approval(self):
        for pending in (True,False):
            api=RepositoryAPI();api.roles['maintainer']='read'
            if pending:api.memberships['maintainer']={'state':'pending','role':'member'}
            else:api.members=[]
            with self.assertRaises(mod.HumanDecisionRequired):verify(api,reviewer_policy=SELECTED)

    def test_native_reviewer_identity_is_bound_to_permission_result(self):
        api=RepositoryAPI()
        def changed(path):
            value=api(path)
            if '/collaborators/' in path:value['user']['id']=999
            return value
        with self.assertRaisesRegex(mod.AuthorityError,'identity differs'):
            mod.verify_proposal(api.proposal,7,REPO,'finite-review[bot]',github=changed,reviewer_policy=SELECTED)

    def test_permission_loss_during_final_check_blocks_issuance(self):
        api=RepositoryAPI();api.members=[];api.roles['maintainer']='admin';reads=0
        def changed(path):
            nonlocal reads
            value=api(path)
            if '/collaborators/' in path:
                reads+=1
                if reads>=3:value['role_name']='read'
            return value
        with self.assertRaisesRegex(mod.HumanDecisionRequired,'withdrawn'):
            mod.verify_proposal(api.proposal,7,REPO,'finite-review[bot]',github=changed,reviewer_policy=SELECTED)

    def test_existing_merged_record_survives_access_loss_without_fake_review(self):
        api=RepositoryAPI();api.roles['maintainer']='read';api.reviews=[]
        result=verify(api,require_live_review=False,reviewer_policy=SELECTED)
        self.assertEqual(result['status'],'historical-provenance')
        self.assertIsNone(result['reviewId'])
        self.assertFalse(any('/collaborators/' in x or '/reviews?' in x for x in api.calls))

    def test_historical_mode_still_rejects_tampering_unmerged_or_divergence(self):
        for kind in ('tamper','unmerged','diverged'):
            api=RepositoryAPI();api.roles['maintainer']='read';api.reviews=[]
            if kind=='tamper':api.blobs[MERGE]={'bad':'bytes'}
            if kind=='unmerged':api.pr.update(merged=False,state='open')
            if kind=='diverged':api.compare='diverged'
            with self.subTest(kind=kind), self.assertRaises(mod.AuthorityError):
                verify(api,require_live_review=False,reviewer_policy=SELECTED)

    def test_historical_mode_never_authorizes_an_open_proposal(self):
        with self.assertRaises(mod.AuthorityError):
            verify(RepositoryAPI(),require_merged=False,require_live_review=False,reviewer_policy=SELECTED)

    def test_explicit_strict_mode_is_required(self):
        self.assertIsNone(common.governance_policy({}))
        self.assertEqual(common.reviewer_policy({'governance':MODE}),SELECTED)
        bad=(None,{}, {'mode':'unknown'},dict(MODE,extra=True),
             dict(MODE,confirmedLegacyAcceptances=['not-a-hash']),
             dict(MODE,confirmedLegacyAcceptances=['a'*64,'a'*64]))
        for value in bad:
            with self.subTest(value=value),self.assertRaises(ValueError):common.governance_policy({'governance':value})

    def test_legacy_scope_requires_exact_confirmation_after_provenance(self):
        proposal={'payload':{'disposition':'accepted'}}; digest='a'*64
        cfg={'governance':MODE,'repository':REPO,'policyPath':'ci/decision-policy.json'}
        proof={'mergeCommit':MERGE}
        with patch.object(common,'historical_provenance',return_value=proof) as historical, patch.object(common.authority,'document_at',return_value={}):
            with self.assertRaisesRegex(ValueError,'explicit carry-forward'):common.persisted_risk(cfg,digest,proposal,None)
            historical.assert_called_once()
            approved=dict(cfg,governance=dict(MODE,confirmedLegacyAcceptances=[digest]))
            self.assertEqual(common.persisted_risk(approved,digest,proposal,None),proof)
            with self.assertRaises(ValueError):common.persisted_risk(approved,'b'*64,proposal,None)

    def test_future_acceptance_uses_verified_merge_policy_not_current_access(self):
        cfg={'governance':MODE,'repository':REPO,'policyPath':'ci/decision-policy.json'}
        proof={'mergeCommit':MERGE}
        with patch.object(common,'historical_provenance',return_value=proof),patch.object(common.authority,'document_at',return_value={'governance':MODE}) as document:
            self.assertEqual(common.persisted_risk(cfg,'a'*64,{'payload':{'disposition':'accepted'}},None),proof)
            self.assertEqual(document.call_args.args[-1],MERGE)

    def test_invalid_provenance_is_never_carried_forward(self):
        with patch.object(common,'historical_provenance',side_effect=ValueError('bad proof')),patch.object(common.authority,'document_at') as document:
            with self.assertRaisesRegex(ValueError,'bad proof'):common.persisted_risk({},'a'*64,{'payload':{'disposition':'accepted'}},None)
            document.assert_not_called()


if __name__ == '__main__':unittest.main()
