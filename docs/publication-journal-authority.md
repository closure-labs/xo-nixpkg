# Separate publication authorization from completion bookkeeping

## Measured problem

Publication [41665346636](https://github.com/closure-labs/xo-nixpkg/actions/runs/41665346636)
recorded 2,422 authority-callback reads across nine gates: 282, seven times 286,
and a failed 138-read gate. The last gate failed querying the current Super Admin
roster at the installation's primary rate limit. Cache publication was complete;
the admitted OCI copy and its immutable descriptor readback had finished, but
`Journal.complete('handoff')` failed before persisting that fact. A subsequent
read-only check verified the matching public digest and descriptor. These counts
do not include every caller sharing the installation's 5,000-request budget.

## Focused change and assurance tradeoff

Do not repeat the full security admission pipeline solely to save a journal
receipt or return an identical receipt. A receipt describes verified destination
state; it is never an authorization token. Keep the initial controller admission
and every existing publishing-leaf gate. No mutable response or authorization
conclusion is cached. Current membership, repository permission, exact-head
review, findings acceptance, policy, freshness, native posture and protected
main are still evaluated by those unchanged gates.

A revocation after a public write no longer prevents recording that completed
write. This intentionally changes the *metadata-write* guarantee: the journal can
be updated after revocation. It does not allow the next public destination write.
Revocation before the next cache upload, registry copy, tag or release still
blocks that operation. There is necessarily a network race between any
pre-operation check and its operation; this patch neither claims atomic GitHub
review/write transactions nor adds an authority TTL.

The journal retains exact product identity, validated expected/observed receipts,
non-force compare-and-swap branch updates, conflicting-step rejection and guarded
readback. Resume still probes/verifies public destinations and executes fresh
leaf admission. Existing journal success cannot authorize a later invocation.

## Validation and expected benefit

The controller's existing no-transfer fixture changes from four direct full-gate
calls to one (three journal-only calls removed); this is a mock count, not a
production timing measurement. At the observed 286 reads per full gate, each
removed checkpoint represents approximately 286 avoided reads with that ledger.
Actual savings depend on new/existing journal and receipt paths. No production
request or wall-time reduction is claimed before reviewed deployment.

Tests cover post-checkpoint access loss before handoff, revocation after restore
before cache upload, all tag/release leaves, a new eligible reviewer needing an
explicit current-head approval, subsequent membership loss, journal CAS/readback
and receipt integrity. Hosted full validation is required before merge. Changing
native reviews/rulesets, historical provenance validation or risk acceptance is
outside this change.

GitHub recommends reducing unnecessary requests and respecting server-directed
rate limits; conditional requests are another possible optimization only where
an endpoint returns 304, not a justification for caching authority decisions:
https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api
