# GitHub-native repository secret policy migration (draft)

This draft implements `github-native-secret-observation-v1`; it is not activated
on this branch and must not be merged before review and the bootstrap below.
No release restart, permission expansion, risk acceptance or cleanup is performed.

## Policy and guarantee change

Require native secret scanning and push protection enabled, two matching complete
`hide_secret=true` open-alert inventories, stable exact candidate/protected-main
heads and settings, collection within120seconds, and freshness within300seconds
of collection start. The bounds are20pages of100 per pass. An open alert,
permission/API error, hidden-secret/schema failure, pagination cap/cycle/redirect,
race, future/stale clock or changed policy blocks. No raw-response fallback.

This observes provider/default native coverage; it conservatively blocks any
unclassified open alert rather than excluding it. Optional non-provider and validity
settings remain unchanged. It is NOT exact-commit/full-history completion and NOT
Gitleaks-equivalent coverage. No baseline or broad exception is introduced.
Scan-history404 remains unavailable/inaccessible, never manufactured success.

## Credential and required-check ownership

`native-secret-observation.yml` runs only protected current-main controller code
from metadata-only `workflow_run` or main schedule/manual events. It never checks
out a candidate. It authenticates the live run and repository PR/queue head before
minting observer credentials. The observer App token requests only Administration,
Metadata and Secret scanning alerts reads; ordinary source/run/PR metadata uses a
separate GitHub token through a GET-only adapter. Check publication uses the
separate GitHub Actions check-write token, preserving required context ownership
(`Repository security audit`, App15368). Decider maintains human authority checks.
Untrusted candidate CI receives no App key, observer token or alert access.

The source preflight is named `Repository preflight`, remains same-run/attempt
bound, runs pure checks, and makes no native-authority claim. Native observations
are separately posted by the trusted controller. Changed-workflow bootstrap tests
are explicitly proposed-code validation without cache or observation authority.

## Required staged bootstrap (no forged current-base success)

A one-shot migration PR cannot manufacture the new protected-main check while
main still lacks its observer. Therefore install the reviewed controller first:

1. A separately reviewed bootstrap change adds only the native policy/validator,
   controller, observation workflow and focused tests. Leave all legacy CI/release
   gates intact in that bootstrap. Normal current policy and exact-head maintainer
   approval still apply; do not use a rule bypass or old-product waiver.
2. Once the bootstrap is on main and its authenticated check is demonstrated,
   refresh/review this integration against that main. It renames pure preflight,
   retires Gitleaks execution/dependencies, migrates evidence schemas and replaces
   the publication prerequisite. Until then a missing trusted native check is a
   real blocker, not a success to be synthesized by candidate tests.

This DRAFT may be reviewed before that installation, but is not merge-ready.
Bootstrap-only tests skip four stage2-only boundary tests when the old gate is
still installed; the complete integration runs all of them. This is explicit
sequencing, not a claimed native observation or permission waiver.

## Qualification, reuse, publication and preserved gates

New preflight/cache receipts use schema2 and a native-policy digest; old receipts
cannot provide current preflight or build-reuse authority. New product/scans
metadata carries the policy binding. A legacy-policy product cannot be rescanned
into a new-policy release identity. New qualification must pass a fresh protected-main
native observation before attestation. After the eventual migration merge, start
new policy-bound qualification and security/release proposals; do not reuse old
qualification41047992796/publication41062449856 or an implicit #200 exception.

Every existing publication boundary now performs live re-observation with the
read-only observer token; a saved receipt or earlier check cannot substitute.
The separate existing `xo-nixpkg-decision-publication` call, Grype CycloneDX
vulnerability inventories, exact-product decisions, immutable roots/NARs,
attestations/provenance, current SuperAdmin review and signer authority remain.
Historical accepted vulnerability evidence remains readable; current admission
requires the new policy binding. Product Grype scanning has not been replaced.
Gitleaks had repository/history/fixture inputs, not built-output secret coverage.

## Permission state and owner steps

Read-only verification confirmed Decider App5384448 (`cl-decider`), actual
closure-labs installation grants for `secret_scanning_alerts:read`,
`administration:read`, `metadata:read`; an XO-only token with exactly those reads
returned enabled scanning/push protection and zero hidden-secret open alerts with
complete pagination. The token was revoked. Scan-history returned404. These
capability results are not a completed exact-head audit or this workflow's live test.

For auditing the user-performed change: organization Settings -> Developer settings
-> GitHub Apps -> cl-decider -> Permissions & events -> Repository permissions ->
Secret scanning alerts -> Read-only; save, then approve the permission update on
its closure-labs installation. App permission configuration can affect installation
grants beyond xo-nixpkg. It is not repository-only configuration; runtime observer
tokens are separately limited to `closure-labs/xo-nixpkg`. No further change is
requested or performed by this draft.

## Validation and pending work

Local focused checks already passed:47 native-policy/controller tests,16 preflight,
38 build-reuse tests, and actionlint on changed workflows. Later source-only
credential-adapter changes receive syntax/actionlint sanity before draft publication;
hosted CI supplies full suite, Nix/toolchain and live workflow validation. No local
Nix evaluation/build, Gitleaks scan or diagnostic experiment was run.

Do not merge/activate or restart releases without separate user review. After a
verified migration, independently verify and then cancel only superseded relevant
active work and close only obsolete security/release proposals. Preserve history
and unrelated #179 dependency / #195 CodeQL updates. Nothing is cancelled/closed here.
