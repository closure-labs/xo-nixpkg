# Native maintainer governance: inactive migration proposal

This draft changes no live workflow, ruleset, environment, risk decision,
credential or publishing gate. Its Python reference model is test-only; it is
not a signature verifier, issuer or deployment authorization. Production still
uses the legacy access-loss policy until an explicitly reviewed cutover.

## Baseline and chosen objective

Observed protected main: `5b659dd786bcc874f7d069c004b5117fb6822dcc`.
Ruleset 21015412 is active, requires the merge queue and six App-bound checks,
but requires **zero** native approving reviews. Both `publication` and `release`
environments restrict branches but have **no required reviewers**. Therefore
removing `Maintainer decision authority` now would leave a review gap.

The chosen new objective is that loss of maintainer access prevents **future**
approvals. It does not revoke an already issued findings-risk acceptance.
Existing subject/profile/finding scope, explicitly configured expiry and explicit
revocation still apply; new or uncovered findings require a new human decision.
An acceptance is not a clean-security assertion. Fresh scans, database ages,
producer identity, exact outputs and publication destination integrity remain
independent checks. Organization-wide Super Admin membership is not a necessary
proxy for repository maintenance authority.

## Proposed standard mechanisms

| Concern | Target mechanism | Remaining narrow responsibility |
| --- | --- | --- |
| Code and decision-record merge | Native required reviews, stale-review dismissal, last-push approval, existing merge queue and CI | Confirm minimum reviewer role; native counted reviews normally use write access |
| Explicit findings acceptance | Native review of a clearly scoped findings decision, followed by one trusted issuance | At issuance, bind actual human review and current repository eligibility to exact immutable scope |
| Persisting accepted risk | GitHub-native attestation from a pinned protected-main issuer over the acceptance subject | Pinned `gh` verification at each artifact trust boundary; explicit revocation lookup, not a live role check on the historical approver |
| Publication authorization | Protected `publication` environment if a separate human release approval is retained | Exact approved product/source/run/attempt, freshness and destination checks after any wait |
| Artifact authenticity | Existing GitHub attestations and exact NAR/asset/producer verification | Unchanged cryptographic verification, no cached passing authorization |

This can retire repeated Super Admin roster, historical review and permission
reconstruction at every publisher checkpoint. It cannot yet be measured as a
production saving. Native merge review is an approval gate, not an authenticated
finding-disposition format; the explicit findings record remains necessary.
Build provenance does not itself mean a human accepted vulnerabilities.

The likely minimum is one small trusted issuance step, not a new controller:
resolve one immutable qualified finding scope; verify existing producer proof;
obtain the real native review; check the reviewer's current eligible repository
role; recheck the head/scope; attest the acceptance through the native service.
No acceptance may be made from a candidate-supplied reviewer/role/verification
boolean. The reference model injects those outcomes solely as test doubles.

Native environment approval could replace the findings PR instead. That is an
alternative, not an additional approval silently stacked on top. Decide the
approval surface before implementing either issuer.

## Important native limits

- Environment required reviewers need only **read** repository access. That is
  not equivalent to a maintain/admin minimum; a small eligibility check at new
  issuance remains necessary if that minimum is chosen.
- The review-history API identifies a workflow run and environments, but its
  documented result has no workflow-attempt binding. Proposed initial issuer:
  allow only attempt 1 and require a new run for retry; do not reuse approval
  from an earlier attempt. This conservative proposal is not deployed.
- Required environment reviewers allow one of up to six configured users/teams
  to approve. They do not implement an arbitrary quorum.
- With prevent-self-review enabled, a sole maintainer cannot approve a job they
  triggered. Normal bot-originated workflows can preserve the current path;
  direct human dispatch needs a second eligible reviewer. Do not disguise an
  initiator to bypass that rule.
- Native PR authors cannot approve their own PRs. Bot-authored assistant work
  can be reviewed normally; human-authored changes need another maintainer.
- A generic protected-branches environment setting needs negative testing; use
  an explicit main-only deployment policy if equivalent protection is uncertain.
  Verify tag, fork and non-main rejection, not just a configuration checkbox.
- Environment approval must precede credential availability. Repository-scoped
  duplicate secrets, independently scoped App tokens and other writer workflows
  could bypass that environment. Retain their existing guards until an inventory
  and hosted negative tests prove the replacement covers every writer.

## Decisions required before implementation/activation

1. Confirm the minimum future approver role and native reviewer pool. The model
   uses maintain/admin provisionally; it does not assume write is equivalent.
2. Keep a separate human publication approval, replacing product-review PRs with
   an environment gate, or allow automatic publication of qualified products
   covered by valid acceptances? Do not remove the product approval by default.
3. Choose an explicit legacy-sealing ceremony and clarify expiry/revocation.
   Existing records are not retroactively native-attested. A trusted current
   validation plus explicit human confirmation can seal their exact accepted
   scope at cutover; this must not fabricate historical permission evidence.
   Decide whether dismissing a later review is an explicit revocation or only a
   pre-issuance review action. Role loss alone is already decided: not revocation.

## Staged cutover, with legacy protection retained

1. Resolve those decisions. Implement the small issuer, native attestation
   verifier integration and writer inventory in another reviewed draft. Keep
   production behavior unchanged; no fixture or model is authority.
2. Obtain action-time approval for exact native rules/environment changes.
   Enable at least one required review, stale dismissal and last-push approval;
   retain all six current required checks, source App IDs and queue. Configure
   exact reviewer pool, main restriction, self-review/bypass policy and scoped
   credential custody. Read back complete settings, preserving concurrent edits.
3. Hosted positive and negative trials: missing/ineligible/self approval; stale
   head; role loss before issuance; role loss after sealing; wrong run/attempt,
   source, issuer, subject or policy; unreviewed findings; explicit revocation;
   expired/changed scan evidence; tag/fork/non-main; every alternate writer.
   Verify real native `gh` signatures and unchanged NAR identities. Mock tests do
   not prove native platform behavior or credential isolation.
4. Seal only explicitly confirmed legacy acceptances. Do not copy current
   approval booleans into old records or relabel old provenance.
5. Only after verified equivalent enforcement, separately approve the surgical
   removal of the custom required context and redundant historical live-role
   reconstruction. Preserve artifact/provenance checks and findings scope.
6. Verify a normal protected merge and publication, then observe API counts.
   Roll back to overlapping legacy protection on failure; no broad bypass or
   unattended settings rollback that overwrites concurrent changes.

The test-only readiness assessment always reports `activation: inactive` and
`authorityClaim: false`, including when all modeled prerequisites are satisfied.
It is not permission to change settings or publish packages.

## Build-reuse snapshot assessment (separate from governance activation)

Current `ci/build-reuse.py` has three exact workflow digests identifying contracts
that cannot export/attest PR receipts. This is a negative availability filter;
selected proof still receives full source/run/attempt/signature/output checks.
An unknown digest deliberately falls back to historical discovery. #264 removed
an incorrect assertion that an archived snapshot must equal today's CI bytes.

Controlled measurement with the current protected code and 30 empty PR runs:
known digest: **1 run-list request, 0 artifact lists**; unknown/comment-changed
workflow: **1 run-list plus 30 artifact lists**. These are mocked deterministic
request counts, not production wall-time or observed API savings. Current CI
matches the reviewed pinned snapshot. The maintenance weakness is performance
fallback after harmless changes, not lost validation or a recurring test error.

A standard alternative is discovery restricted to native `merge_group` and
protected-main `workflow_dispatch` producers. It removes digest/fixture upkeep,
but uses two list calls and abandons optional historical PR artifact reuse.
That is a cache-availability tradeoff, not a reason to relax attestations. Do not
add a YAML inference engine or silently change producer compatibility. Keep the
current filter until a separate focused test/measurement establishes a net gain;
no build-reuse production code is changed by this proposal.

## Primary references

- [Native required reviews and stale approval behavior](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches)
- [Environment reviewer roles, quorum and self-review](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [Workflow review-history API](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run)
- [Native artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
- [Attestations do not guarantee security](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-supply-chain-security)
