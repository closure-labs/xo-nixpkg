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

For #119, complete retained and public NAR downloads match their respective
admitted hashes but differ at 124 latest, 126 stable and 131 rolling paths under
the same immutable store names. Every changed path is a retained Turbo build
log, embedded documentation asset or generated runtime source/bundle/map.
Generated mixin and locale indexes contain identical lines in different orders;
logs include elapsed build times and documentation includes timestamped search
assets. These are observed nondeterministic build outputs, never an exemption
from exact byte approval or remote conflict checks. The [file-hash comparison](benchmarks/xo-product-119-nar-comparison.json)
records each difference and verified NAR identity. Admitted records and public
objects remain unchanged; deterministic-build remediation is separate.

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

## Package 4: independent destination recovery

A versioned destination result distinguishes authenticated absence, partial
inventory, verified identity, conflict and service unavailability. Cache
inspection precedes store import and uploads only missing roots; conflicting
NAR identities never overwrite existing public objects. Completion requires
fresh readback. XO's admitted retained packets use original signed metadata
bytes before any payload materialization, and OCI retries verify immutable
manifest/descriptor identities before copying absent content.

Maestro reconciles immutable hosted bytes and independently inspects FlakeHub
through the exact-version immutable source/revision HEAD chain. A current
destination skips its upload. Upstream handoff verification reads signed
metadata without downloading NARs. Native actual-XO identity still comes from
local or fresh public Nix metadata and is checked against the scanned runtime
context and independent upstream authority. Explicit Actions run recovery
keeps the historical full-artifact transport interface.

Official Maestro and XO destination checkpoints carry version1 verified
receipts in version2 CAS journals. Package3 readers must be deployed first.
An old completed step preserves history but never suppresses current remote
inspection. A matching proof repeats live authority without duplicate journal
writes. Rollback requires a reader that understands journal version2.

## Package 5: startup and notification boundaries

The decision-event relay is the sole new raw workflow command exception. Its
exact template has an empty permission map, one constant printf, no checkout,
no Nix, no artifacts, no credentials and no write. It signals activity only.
Protected-main authority re-authenticates current membership, exact reviewed
head and human decision using the unchanged workflow path and check signer.
Adversarial contract fixtures reject additions to the relay.

Controller and verdict tasks start with an empty development package profile;
each native leaf supplies its own runtime inputs. Reconciliation retains one
running and one coalesced pending wakeup, repair schedules and serialized
publication. Authority jobs retain per-event identity because each exact-head
check must complete. Qualification/audit overlap remains disabled by default.

XO's queue now listens for authority completion. The historical review observer
path remains a rollout fallback until a protected hosted authority-to-queue run
is verified; then set declared `XO_AUTHORITY_WAKEUPS_VALIDATED=true` to retire
its work. This gate defaults false. PR validation alone does not establish that
protected-main rollout condition, and this refactor does not bypass it.

Maestro's release-continuation path already rejects irrelevant authoritative
callback metadata before journal/packet materialization. Its marker, request
expiry, source, run/attempt and completed-producer checks remain intact.

## Package 6: classification and scan inputs

Five version1 dependency fingerprints separate raw inventory/generator inputs,
normalization, runtime context, fresh observations and attestation inputs.
They are additive diagnostics, never authorization. Existing authoritative
inventory, subject, context and product digests remain intact. Observations and
attestations are regenerated for each invocation; fingerprint equality does not
reuse either. XO raw-inventory reuse requires the exact closure/NAR identities,
derivation documents, generator bytes, verifier version, source tree and hosted
job identity. Every hit revalidates regular files and hashes.

XO maps current controller/test files explicitly and retains full validation
for unknown paths. Weekly complete validation disables Actions imports.
Maestro's existing fresh-media schedule and disabled audit/qualification
overlap are unchanged. CodeQL, Gitleaks, Zizmor and scanner canaries remain.

The XO advisory controller prepares one online, caller-anchored database for
three sequential reports, revalidates all snapshot bytes before/after use, and
keeps the stricter24-hour advisory age and4-hour preparation age. Admission
retains48 hours. The historical one-channel command, all three artifact names,
retention and applicability rationale remain available.

When a successful qualification exactly matches current source and producer
run/attempt, signed product/scans plus digest-bound inventory assets can extend
the advisory inputs. Original supply components, graph and properties are
retained; all distinct native instances and installed paths are included. Differential fixtures
prove no original coverage disappears. No eligible exact-source packet means
the original supply inventory path runs normally. Invalid provenance or hashes
block. This introduces no cross-tree Actions artifact reuse.

Runtime inventories use a separate exact-name reader capped at 64 MiB per
member and 180 seconds, within a 300-second discovery/materialization budget.
Producer, packet descriptor, byte size and hash are checked before use. The
ordinary metadata reader retains its 16 MiB limit; closure members cannot use
the inventory reader.

Protected-main qualification/refresh regenerates current sidecars, observations
and independent attestations after rollout. Historical decisions, signed
products and observations are never rewritten to manufacture fresh evidence.
Comparable fixture results show zero duplicate packet payload fetches, zero
closure transfers on a verified publication retry, one raw generation for two
identical job inputs, and one database preparation for three advisory reports.
These are operation counts, not production percentage savings claims.
