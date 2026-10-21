# CI resilience rollout

The refactor preserves exact product approval, independently attested hosted
builders, protected-main authority and separately credentialed publication.
Source approval does not authorize a product. Reconciliation remains scheduling
only; every write repeats live authority.

## Package 1: publication correctness

Maestro resolves drafts through an authenticated listing (at most 1,000
releases), validates draft creation and retains its ID for subsequent reads.
Hosted asset hashes, notes, source, tag and inventory are still verified.
Both publishers require fresh public NAR metadata before returning success.
A weekly protected-main consumer downloads the latest accepted product into a
disposable store and verifies recursive contents, trust and exact root hashes.
The probe reports absence or conflicts as failures; it never writes public data.

XO #120 was already merged at the implementation baseline, and its guard is
preserved. Product #121's exact-head review and merge were independently read
back. Its successful publisher run is 39559655391. Fresh HTTP readback matched all eight cache roots to the approved hashes.
The public journal records cache, handoff and XO tag completion, and the public
OCI manifest digest was read back and verified. A green historical journal
alone is not proof of present remote state.

Independent QA and security review found no blocker. Native fixtures include
invalid draft inventories/responses, changed release IDs, partial recovery and
remote hash failures. An independent real-Nix consumer test also rejected a
wrong signing key and corrupt compressed NAR bytes. The weekly probe tests the
latest accepted product; an approved product still awaiting publication fails
this expectation rather than silently falling back to an older product.

For #119, retained closure manifests show differing NAR hashes on the same
three XO root paths. Stable and rolling have identical closure membership;
latest additionally changed three automation helper paths. Inventory differences
are confined to closure/derivation-document bindings. These observations do not
locate the differing file contents. Admitted records and public objects remain
unchanged. Comparing retained exact NARs is still required to establish a cause.

No percentage savings are claimed from the incident-heavy audit sample.

## Package 2: bounded operations and queues

Transport uses monotonic remaining-time budgets, including across nested helper
processes. Metadata reads are bounded to 30 seconds, optional discovery and
receipts to 90 seconds, an eligible payload to 180 seconds, and the entire
optional pre-import phase to 300 seconds. Required evidence and upstream handoff
materialization share a 900-second total across transport fallbacks. Import and
recursive verification share 600 seconds after optional availability fallback
ends. Public-cache readback remains bounded to 120 seconds. Builders retain
their existing job policy.

Timeout cleanup sends TERM and then KILL within a ten-second grace, tracking
nested process identities so detached or reparented descendants cannot outlive
an outer supervisor. Optional pre-import availability failure becomes a miss;
invalid provenance, hashes and archives block, as do all import/verification
failures after import begins.

Queue reconciliation reads exact-head native state before mutations and handles
closed, merged, queued, changed-head, awaiting-review and awaiting-checks states.
Auto-merge and explicit enqueue both bind the expected head. An ambiguous
mutation is read back once; it is not blindly retried. API failure remains a
blocked result, with fixed diagnostics instead of raw service responses.

The native XO audit captures its Nix executable before entering the packaged
helper. This preserves the installed Determinate client when its daemon is newer
than the helper's Nixpkgs client; the earlier client failed to decode the daemon's
BuildResult status16. It does not change the protected candidate builder or the
flake contract being evaluated.

## Package 3: metadata and immutable bytes

Packet inspection, bounded metadata reads and full materialization are separate
APIs. An exact-run active publication/refresh is inspected before downloading
closure payloads. A prior successful publication suppresses bulk work only after
retained immutable observation expiry is checked. Missing retained metadata uses
the normal authenticated materialization path; API or integrity failure blocks.

Within one hosted job, materialization is keyed by OCI manifest digest, packet
digest, producer and verifier version. Every reuse revalidates the complete file
inventory, sizes, hashes and regular-file constraints, then provides regular
hard links to those job-local bytes. Callers repeat producer attestations and
live authority; no authorization result is cached. Changed jobs/attempts or
verifier inputs require new materialization. Corruption blocks rather than
silently redownloading evidence to hide it.

Scheduling records include exact source/controller revisions, run/attempt,
product/packet identities when known, fixed action/reason codes and an explicit
false authority claim. Version1 stage summaries record measured durations,
cache outcomes, transferred body bytes, freshness and destination/checkpoint
fields. Summaries exclude argv, credentials and raw API responses.

This package also deploys backward-compatible readers for legacy journal1 and
journal2 verified destination receipts. It does not emit journal2. Receipt
writers are a later rollout step, so rollback must retain these readers once
new receipts exist. A legacy completion record alone remains insufficient
proof of present remote state.
