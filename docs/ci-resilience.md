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
