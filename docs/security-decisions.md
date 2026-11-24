# Native GitHub reviews for code and releases

GitHub PR reviews, CODEOWNERS and the native merge queue own approval. The same
mechanism reviews code changes and exact release requests. Publication does not
request a second environment review or use `/decider approve` comments.

## Review a release

1. Qualification builds and scans all four distributed profiles, checks native
   repository secret posture, and attests the exact product and scan documents.
2. `Propose qualified release` authenticates the successful main producer,
   retrieves inventories without closure payloads, and uses the shared planner
   to prepare the request and complete normalized findings.
3. The Decider opens or updates one ordinary release PR. Its only changed file
   is `.github/release-request.json`. The PR body identifies the source,
   qualification run/attempt, product and scan hashes, destination purpose and
   per-profile finding counts, with a link to the complete `publication-review`
   artifact. Identical retries preserve the existing head and review.
4. A maintainer reviews the exact request and findings using GitHub's **Approve**
   review. Native rules require an approving review, CODEOWNERS approval, stale
   review dismissal, resolved review threads and approval after the last push.
   Auto-merge requests entry to the native queue once required checks pass.
5. Merging the request triggers `Publish reviewed products`. Its read-only
   preflight authenticates the evidence again. The publishing job rechecks the
   same request before every destination write, then records destination facts
   in the existing compare-and-swap publication journal.

The request includes the complete immutable product document plus its hash,
source revision, exact qualification run and attempt, scan hash, normalized
findings hash, complete finding counts, policy hash and `rolling` or `release`
purpose. A changed product, scan, attempt, policy or purpose requires an updated
PR and a new native review. The producer's latest attempt must remain successful.

A review accepts the recorded findings for these exact bytes and purpose.
Risk acceptance no longer carries forward to a new scan or product. Native
GitHub review and merge history are the approval record; there is no security
supersession graph, security-decision PR, separate product-decision PR, custom
App-origin authority check or live team-membership voting engine.

## Shared planning and validation

`ci/decisions/native_approvals.py` owns request schemas, complete profile coverage,
product/scan bindings, protected-main ancestry and native protection validation.
The proposal planner, publisher and policy audit use those same validators.
The existing shared evidence validators retain scanner/database health,
attestation verification, original product provenance, root and NAR identities,
runtime contexts and repository secret-policy bindings.

`ci/publication-plan.py` has read-only `plan`, `request` and `verify` operations,
and a publishing-boundary `gate` operation. No plan, report or destination receipt
substitutes for the request on protected main. The gate also authenticates the
actual running main-branch publisher workflow and current run attempt. It
rechecks the current request, policy and live repository protections for every
write. A newer approved request supersedes the prior target through ordinary Git
history; an old in-flight publication stops if its request is no longer current.

The publication environment restricts deployment to protected branches and
provides no additional approval mechanism. Its administrator bypass is disabled.
Only the fixed main-branch publisher job can write. Tools are built from the
immutable protected workflow revision before write credentials are minted. The
writer needs repository contents write and Actions read; it no longer needs
organization membership, PR-review or administration authority. Native posture
and secret observations use a separate read-only observer.

## Evidence retention and retries

Actions retains qualified products, inventory-only bundles and review artifacts
for 90 days. Daily qualification refreshes inventories and scanner observations;
the first day of each month performs a fresh qualification to renew original
closure transport before artifact expiry. Pushes changing only the reviewed
release-request file do not rebuild qualification, preventing a release loop.
A manual fresh qualification remains available after failed scheduled renewal
or expired artifacts.

Pre-migration private OCI references remain readable as historical transport
recovery. Their decision dispositions, graph shape and reviews grant no native
publication authority. The old ledger remains intact as historical data; its
four competing security leaves are no longer an active release selector.

Publication still verifies the public cache and exact immutable tags, refuses
conflicting remote bytes, restores authenticated closure transport without
rebuilding, and records completed destination facts. A verified retry can reuse
those facts and avoid repeated transfers, but must pass the current native gate.
An exact completed public handoff supplies retry metadata directly; a first
native publication uses its fresh Actions artifact without reading the retired
decision ledger. Historical ledger references are limited to restoring old
transport when an original artifact has expired.
The clean-store consumer reads the single native reviewed product and checks
completed publication receipts, public NAR hashes and signatures.

## Activation and operations

See [the migration procedure](native-approvals-migration.md) for the staged
cutover. `ci/decision-policy.json` is disabled when the migration lands, and
legacy decision commands are removed from the packaged application interface.
The legacy authority and release-reconciliation workflows are retired.

To request a particular qualified product, dispatch `Propose qualified release`
on main with `qualification_run`, optional expected `qualification_attempt`,
and `purpose`. Review and merge the resulting native PR. Dispatching `Publish
reviewed products` retries the current approved request; it cannot select a
different run or purpose. To withdraw a pending target, cancel its workflow and
review a PR removing or replacing `.github/release-request.json`. To disable all
publication, review a policy change setting `enabled` to false.

CI execution approval for external contributors remains a separate GitHub Actions
control. Trusted-author CI admission can run tests; it grants no merge or release
approval. Native PR reviews and required checks still govern every merge.
