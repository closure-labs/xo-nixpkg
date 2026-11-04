# SPDX-License-Identifier: Apache-2.0
"""Executable proposal semantics only; no GitHub, crypto or settings assertions."""
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import sys
import unittest

FIXTURES = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('inactive_governance_model', FIXTURES / 'governance_model.py')
model = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = model
SPEC.loader.exec_module(model)


class GovernanceMigration(unittest.TestCase):
    def issue(self, **changes):
        args = dict(subject='scope-descriptor-digest', findings=['CVE-fixture'], policy='v-next',
                    role='maintain', human=True, review_head='a'*40, current_head='a'*40,
                    issuer_workflow='protected-issuer', run=123, attempt=1, evidence_verified=True)
        args.update(changes)
        return model.issue(**args)

    def consume(self, acceptance, **changes):
        args = dict(current_role='maintain', subject='scope-descriptor-digest', findings=['CVE-fixture'],
                    policy='v-next', trusted_workflow='protected-issuer', proof_verified=True,
                    revoked=False, now=100)
        args.update(changes)
        return model.consume(acceptance, **args)

    def test_past_acceptance_survives_access_loss_but_new_issuance_does_not(self):
        acceptance = self.issue()
        for role in ('read', 'triage', 'none'):
            with self.subTest(role=role):
                self.assertTrue(self.consume(acceptance, current_role=role))
                with self.assertRaisesRegex(ValueError, 'issuance-blocked'):
                    self.issue(role=role)

    def test_different_new_maintainer_must_explicitly_approve(self):
        with self.assertRaises(ValueError):
            self.issue(role='maintain', review_head='b'*40)
        self.assertTrue(self.consume(self.issue(role='admin')))

    def test_stale_head_bot_or_unverified_evidence_cannot_issue(self):
        for changes in ({'review_head':'b'*40}, {'human':False}, {'evidence_verified':False},
                        {'run':True}, {'run':0}, {'attempt':2}, {'attempt':True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.issue(**changes)

    def test_access_loss_never_waives_scope_signature_policy_or_revocation(self):
        acceptance = self.issue()
        for changes in ({'subject':'other'}, {'findings':['new-finding']}, {'policy':'old'},
                        {'trusted_workflow':'candidate'}, {'proof_verified':False}, {'revoked':True}):
            with self.subTest(changes=changes):
                self.assertFalse(self.consume(acceptance, current_role='none', **changes))

    def test_explicit_expiry_is_not_silently_extended(self):
        acceptance = replace(self.issue(), expires_at=100)
        self.assertTrue(self.consume(acceptance, now=99, current_role='none'))
        self.assertFalse(self.consume(acceptance, now=100, current_role='none'))

    def test_current_observed_native_settings_cannot_retire_legacy_guards(self):
        result = model.readiness(native_reviews=0, stale_reviews=False, last_push_approval=False,
            environment_reviewers=False, environment_main_only=False,
            alternate_writers_verified=False, issuer_implemented=False,
            legacy_sealed=False, unresolved_decisions=True)
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(len(result['missing']), 9)
        self.assertFalse(result['authorityClaim'])

    def test_each_missing_prerequisite_independently_blocks_retirement(self):
        complete = dict(native_reviews=1, stale_reviews=True, last_push_approval=True,
            environment_reviewers=True, environment_main_only=True,
            alternate_writers_verified=True, issuer_implemented=True,
            legacy_sealed=True, unresolved_decisions=False)
        result = model.readiness(**complete)
        self.assertEqual(result['status'], 'ready-for-independent-review')
        self.assertEqual(result['activation'], 'inactive')
        self.assertFalse(result['authorityClaim'])
        for key in complete:
            broken = dict(complete, **{key: True if key == 'unresolved_decisions' else 0})
            with self.subTest(key=key):
                self.assertEqual(model.readiness(**broken)['status'], 'blocked')

    def test_proposal_is_explicitly_inactive_and_unresolved(self):
        proposal = json.loads((FIXTURES / 'governance-proposal.json').read_text())
        self.assertEqual(proposal['activation'], 'inactive')
        self.assertEqual(proposal['approvalAccessLoss'], 'blocks-future-issuance-only')
        self.assertEqual(len(proposal['unresolved']), 3)
        for field in ('liveSettingsChanged', 'issuerImplemented', 'alternateWritersVerified', 'legacySealed'):
            self.assertFalse(proposal[field])


if __name__ == '__main__':
    unittest.main()
