<!-- SPDX-License-Identifier: Apache-2.0 -->
# Immutable reads within one admission

An admission call may reuse successful decision-file Contents metadata for a
full 40-character commit SHA, and successful ancestry status between two full
commit SHAs. The in-memory map is created inside `gate()` and discarded when
that call returns. Another checkpoint or process starts with an empty map.

The allowlist is deliberately narrow: only canonical decision JSON paths under
`automation/decisions/security` and `automation/decisions/releases`, and exact
SHA-to-SHA comparisons. Branch refs, arbitrary files, policy paths, query
variants, PR associations, PR heads/files/reviews, timelines, user permissions,
team membership, required rules and current-main reads never qualify. Historical
PR metadata is mutable and is not made immutable by a merged PR number.

Inline bytes are Git-object-hash checked before retention. Large-blob metadata
still flows through the existing blob-byte identity validation and strict JSON
parsing on every use. Cached facts are copied on return, bounded to 256 entries
and 8 MiB, and contain no authorization conclusion. Errors, malformed metadata
and failed ancestry results are not retained. Capacity exhaustion performs the
original live read instead. All existing main/head/timeline/policy race checks
still run, including the final complete-ledger refresh.

## Request-count evidence

Publisher 41265822364, after the attestation-material change, recorded one
304-call authority callback and nine 308-call callbacks: 3,076 forwarded API
reads. The four additional reads bind local attestation verification to current
repository and owner IDs. These counters exclude verifier-internal traffic and
can undercount transport retries. Failed publisher 41250272572 explicitly hit a
5,000-request core limit with zero remaining; the retry deadline correctly
failed closed instead of sleeping beyond its budget.

Focused fixtures execute the real admission path with eight superseded security
ancestors, one active risk decision and one active product decision, while only
the external API and signature verifier are mocked. With the existing raw-Git
byte cache already warm, ordinary producer admission changes from 302 to 262
forwarded reads. A distinct trusted rescan producer changes from 304 to 264.
Both save 40 calls: 30 repeated Contents reads and 10 repeated SHA comparisons.
The sequence of all other API requests and the admission result are identical.

Applied to the ten observed gates, 400 fewer reads would mean 3,076 to 2,676,
approximately 13%. This is a projection from deterministic fixtures, not a
measured production speedup. The remaining live reads are intentionally retained.
No authority TTL, cross-gate cache, relaxed retry policy or attestation shortcut
is introduced; pinned `gh` still cryptographically verifies each use as before.

Fixtures also cover withdrawn review/membership, historical PR head/file/timeline
races, final main/policy changes, large-blob corruption, malformed responses,
permission/rate-limit failures, response mutation, strict URL allowlisting and
bounded fallback. Hosted CI remains required for integration and Nix validation.
