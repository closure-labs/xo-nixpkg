<!-- SPDX-License-Identifier: Apache-2.0 -->
# Dependabot CI admission

Dependabot remains the author. Ordinary governed PRs already accept its authorship
when an eligible human approves the exact current head; no new author exception
is added to the maintainer authority check. Release/security proposals retain
their existing configured-App author and product/security requirements.

## One execution-approval owner

For `dependabot[bot]` (numeric user ID `49699333`), the protected-main CI admission
controller permits only open, same-repository PRs targeting `main` whose complete
immutable merge-base/head trees and hash-verified blobs prove an existing Actions
pin-only update. Workflow/composite files must remain regular files. Actual YAML
`uses` nodes may change only a full commit SHA and adjacent `# vN`, `# vN.N` or
`# vN.N.N` comment, keeping the same action owner, repository and subpath. The new
SHA must resolve from that exact upstream tag, including bounded annotated tags.
New actions, arbitrary workflow changes, modes, aliases, duplicate/ambiguous
keys, missing blobs and incomplete inventories are refused. Candidate code is
never imported, evaluated or executed by the credentialed controller.

The same existing `decision_authority.approval()` verifies an active member of
the pinned Super Admins team with maintain/admin repository permission. Approval
must cover the current head; absent, stale, dismissed or withdrawn review and
lost eligibility never authorize execution. Initiating/rerun actors must be the
official bot or satisfy the existing trusted-actor policy. Review, membership,
PR/base/head and run identity/attempt are checked again immediately before the
single native execution-approval request. Uncertain writes are not retried.

The legacy queue helper does not approve Dependabot execution holds. It reports
`ci-admission-required` and leaves them to this controller. Other updater families
and their existing local queue prechecks are unchanged. The queue can still
request native auto-merge before review; this is neither human approval nor proof
of actual queue enrollment or merge. Required App-bound authority and native
checks remain mandatory, including review of every new head.

## Wakeups and runtime

Successful authenticated review collectors rediscover blocked CI for their exact
current PR head. Held review collectors themselves use the same admission rules.
Trusted-main authority completion (success or mixed failure) also wakes bounded
rediscovery; its conclusion never supplies authority. Cancelled, unrelated,
stale and malformed wakeups fail closed. The existing fifteen-minute schedule
remains a missed-event fallback. No workflow permissions are expanded.

The workflow builds the immutable `ci-admission` package and pinned Python/PyYAML
runtime from protected main before minting the App token. Credentialed execution
uses that store executable directly, with no further Nix/candidate evaluation.

Only the Actions family is supported. Native Nix updates keep their documented
[paired-lock synchronization and manual queue policy](development.md#setup).
A well-formed unsupported family is reported without blocking later supported
runs; corrupt/incomplete metadata and API failures remain visible hard failures.
There is no generic lockfile exemption or automatic reauthoring.

Tests retain the exact CodeQL workflow bytes from XO PR195 (merge base
`c69059918d2947517648b8ed9cb6c74513b63a35`, head
`871c8f7298544d03d29a6e5d3a2d780fe422870c`) and synthetic hostile deltas.
Fixtures prove policy boundaries, not successful live admission or deployment.
