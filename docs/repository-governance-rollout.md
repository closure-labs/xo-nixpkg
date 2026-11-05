# Staged admin-or-Super-Admin governance

This implementation is inactive. `ci/decision-policy.json` remains unchanged;
merging these helpers does not activate a new policy or change GitHub settings.

## Eligibility and approval events

A new findings acceptance or rolling/versioned publication approval may be issued
by a human who is either a repository admin OR an active member of the pinned
closure-labs Super Admin team. Super Admin membership does not additionally require
repository write, maintain or admin access. Repository admins need not belong to
the team. Immutable native user IDs, current access and exact proposal heads are
checked before issuing new authorization; ambiguous or unavailable metadata fails
closed. Losing both qualifying access paths prevents future approvals.

The same person and pool may approve findings and publication. The implementation
retains separate findings and exact-product publication approval events. It does
not interpret “same people” as automatic publication, one approval covering future
products, or removing the rolling/versioned review events. Changing those events
requires an explicit decision.

## Durable findings acceptance

Past accepted risk remains valid after the approver loses access, until its
existing expiry, a superseding decision or explicit revocation. Exact normalized
findings, profiles, security contexts, packet, provenance and scope checks remain.
This is not a waiver of new findings or a transfer of an old approval to another
product. New publication approvals still check current eligibility.

A legacy accepted leaf needs explicit confirmation by its full canonical decision
hash. The policy field `confirmedLegacyAcceptances` is an exact allowlist; no
historical record is rewritten or relabeled. A future acceptance is recognized
using the policy at its independently verified merge commit, not an arbitrary
candidate marker. Missing/tampered merge provenance remains fatal. Rejected and
revoked decisions remain blocking.

## Protected implementation and staged activation

The required App-owned `Maintainer decision authority` check remains in force.
GitHub's counted native PR reviews cannot independently express the selected pool:
a Super Admin member without repository write access may not supply a counted
native review. Do not grant additional write access or require another approver
to disguise that mismatch. No ruleset exception, new permission grant or review
count change is necessary for this staged design.

1. Publish and review the inactive implementation; run hosted packaging and
   integration validation. An earlier implementation publication was blocked
   before execution; fresh specific approval is required before retrying it.
2. Confirm the exact legacy findings decision(s) to carry forward. Current scope
   candidate: #269, canonical hash
   `a7cc9498cbe0a5815f62e469e4d9700b298cbb2de0599faf796738ad1a0d2953`.
   The user explicitly confirmed this exact scope for carry-forward. The record
   has no explicit acceptance-expiry field; preserve it without inventing one.
   Existing evidence-freshness requirements remain unchanged. This implementation
   does not activate the allowlist or accept additional findings.
3. Review a separate activation change on protected main, adding:

   ```json
   "governance": {
     "mode": "repository-admin-or-super-admin-v1",
     "pastRiskAcceptances": "confirmed-merged-provenance",
     "confirmedLegacyAcceptances": []
   }
   ```

   Fill the list only with explicitly confirmed canonical hashes. Every live
   policy must match protected main, and the App-bound required check must still
   be present. CI execution-admission eligibility is unchanged; the chosen pool
   applies only to findings and publication approval, not new execution grants.
4. Run normal current-policy qualification/reconciliation, obtain actual human
   findings/product decisions as required, then publish through normal guards.
   Do not duplicate active runs or reuse stale source/evidence bindings.

A sole maintainer can review genuinely bot-authored proposal PRs. This does not
permit a human to approve their own human-authored PR or bypass native review
rules. The user selected rolling delivery only for this cutover; no new versioned
release is requested. The already released v0.10.2 remains immutable.

Further removal of the App check or adoption of protected-environment approval
requires an equivalent eligibility/sole-maintainer design and separate review.
Artifacts, attestation verification, scanner policy, fresh native posture,
exact-output/NAR identities, current-main checks and alternate-writer protections
are unchanged by this implementation.
