<!-- SPDX-License-Identifier: Apache-2.0 -->
# Build performance and output reuse

The CI gate still runs all selected contracts. A cache hit restores authenticated
build bytes; it does not restore a test result, scanner verdict, security baseline,
product approval, publication permission, tag or release.

## Exact build reuse

The protected base checkout supplies classification, setup and build-controller
code. Candidate sources are data for pinned Nix evaluation and sandboxed builders.
Candidate evaluation has an empty HOME, no inherited credentials or Nix config,
no remote builders, pure evaluation, and forced sandboxing. A workflow bootstrap
whose workflow differs from its protected base uses ordinary validation and emits
no reusable build certification.

The builder exports one deduplicated union of selected application, library and
supporting output closures. A fresh job, with no checkout or candidate execution,
attests only the receipt. The build job has read credentials; only the attesting
job receives OIDC and attestation write permissions.

A consumer checks the successful producer run and attempt, repository, exact tree,
source commit and immutable protected main base, unchanged workflow and launcher,
exact signed invocation and source ref. It independently evaluates current output
and derivation paths before accepting any matching output. It authenticates the
chunk manifest before safe extraction/import, checks each expected NAR identity,
and physically verifies the recursive store contents. Current builds, VM/runtime
contracts, inventories and fresh native scans still run. Missing credentials or
unavailable/expired artifacts produce an explicit cold-build miss; invalid proofs
or altered bytes fail closed.

PR caches require a same-repository PR targeting main and the actual run-associated
base/head and merge parents. GitHub may omit the PR association from historical
run metadata after merge; those candidates are unavailable and the consumer tries
another cache or builds cold. It never reconstructs historical authority from a
current PR response. Supplied but invalid or ambiguous provenance still fails
closed. Queue caches bind their protected base to both the source parent and
exact queue ref. Manual producer runs must be on exact main.
The receipt must match its historical protected workflow and launcher blobs;
the source workflow must match that protected workflow too. After verifying the
exact signed invocation and output structure, a consumer treats authenticated
historical bytes that differ from its current trusted controller as an unavailable
cache candidate. Forged historical hashes, source-workflow changes and invalid
signatures remain hard failures. Controller changes still require a new reviewed
bootstrap before their output bytes can be reused.

Reusable payloads and receipts expire after seven days; timing metadata remains
for 30 days. Qualified release evidence retains its existing durable policy.
Actions artifact transport in this public repository is separate from the private
GHCR decision registry and from admitted public Cachix/release publication.

For cache-service incidents or controller upgrades, manual CI dispatch accepts
`reuse_builds=false` to build without importing Actions artifacts:

```bash
gh workflow run ci.yml --repo closure-labs/xo-nixpkg --ref main -f reuse_builds=false
```

The packaged restore leaf also accepts `XO_NIXPKG_REUSE_BUILDS=false`; other than
the default `true`, only literal `false` is valid. This selects an explicit cache
miss before artifact discovery or imports. All selected validation and runtime
builds still run, and normal Nix substituters remain available. Fully validated
matching-controller builds can still export newly authenticated output receipts.
A proposed workflow update uses the existing bootstrap path described above;
its ordinary complete validation grants no reusable build certification.

## Fresh scanner database

Qualification and retained-product refresh each prepare one new online Grype DB
and retain its scanner version, schema, build timestamp, preparation timestamp and
all file hashes under a caller-anchored receipt. Every profile verifies the same
snapshot before and after scanning, disables updates, and retains its own native
OpenSSL and npm lodash canaries, inventory, raw report and normalized findings.
Database age remains bounded to 48 hours and preparation age to four hours.

The scanner reads the verified snapshot directly. Copying a multi-GiB database per
profile exhausted temporary disk during native acceptance; zero-copy scanning
preserves byte verification without that disk or copy cost.

## Native packaging and transport measurements

On the local acceptance host, removing verified generated addon metadata and the
installed npm node-gyp tool reduced latest XO from 74 store paths / 2,270,465,672
NAR bytes to 55 paths / 2,010,110,608 bytes: 248.3 MiB fewer runtime bytes and 19
fewer paths. Native Argon2, Leveldown and FUSE checks and the XO service VM passed.
Node 22.23.3 and OpenSSL 3.5.9 remain the declared stock Nixpkgs runtime.

For the same original 74-path closure, the old XZ exporter took 1,378.87 seconds
and produced 451,860,480 archive bytes. Zstandard level 3 took 15.51 seconds and
produced 645,171,200 bytes, about 43% more compressed storage. A separate real
empty-store Zstandard round trip imported all 74 paths without builds, preserved
every NAR hash, and passed physical verification: 7.652 seconds export, 9.430
seconds import and 6.616 seconds verification. These are local measurements;
network upload/download, hosted runner load and whole-job savings are unmeasured.
Artifact ZIP compression is disabled for already compressed NAR payloads.

The local acceptance receipts are retained in
[`ci-performance-local-2026-10-20.json`](benchmarks/ci-performance-local-2026-10-20.json).
They identify measured bytes and scopes; they are not release admission.

## Hosted concurrency

Hosted CI defaults to two concurrent runtime builds. Workflow dispatch accepts
`build_jobs=1` to run serially or `2` to use the default. Native CLI execution and
cheap preflight checks remain serial.

One matched pair of successful Ubuntu 24.04 hosted runs used the same source,
`e7516001aacf0248eadb727086495b8451634405`, and produced identical successful
result arrays for all nine preflight and ten runtime targets:

| Runtime build slots | Validation run | Validation job elapsed |
| --- | --- | --- |
| 1 | [39400904119](https://github.com/closure-labs/xo-nixpkg/actions/runs/39400904119) | 37m 53s |
| 2 | [39401010290](https://github.com/closure-labs/xo-nixpkg/actions/runs/39401010290) | 32m 24s |

Two slots reduced the measured validation job by 329 seconds (14.47%). This is
one paired cold bootstrap measurement; it does not establish a repeated-run
average or an artifact-reuse saving. CPU, peak RAM and disk use were not measured.
The larger individual target times in the parallel run also show contention;
future runner or dependency changes may change the tradeoff. The hosted receipt
retains job intervals, all matched outputs and hashes of the eight raw evidence
files in
[`ci-performance-hosted-2026-10-20.json`](benchmarks/ci-performance-hosted-2026-10-20.json).

The runner refills the first completed slot, preserves plan-ordered diagnostics,
runs every target on failure, and promotes result links only after full success.
Cancellation terminates its own build children. The bound remains two. A branch
benchmark cannot certify cache output until its producer workflow is reviewed;
the measured runs are performance evidence, without release or cache authority.

### Hosted decision byte observations

Authority, reconciliation, publication and disposable consumer jobs retain
`xo-decision-byte-reuse-<job>` artifacts. Each `observations.jsonl` row records a
verified public Git object identity, byte count, whether the job reused bytes,
and whether fresh Contents metadata supplied inline bytes. They contain no
review, membership or authorization results. Corrupt bytes still block; current
main, reviews, membership and every write gate are rechecked. These observations
can establish production use of reuse, but do not establish a throughput or
percentage saving without equivalent hosted samples.

Unsuccessful workflow callbacks skip queue startup. Successful callbacks and
the repair schedule still run ordinary live queue validation. Keep
`XO_AUTHORITY_WAKEUPS_VALIDATED` disabled until an eligible updater has actually
reached the queue through authority completion; a decision-record PR or a
successful empty reconciliation is insufficient proof.

### Publication operation evidence

The existing native publisher retains `xo-publication-result` after successful
remote verification. It binds the exact product, source, producer and checked
out controller revision to operation counters, independently of journal bytes.
Counters record entry into closure-packet fetching, cache publication, OCI
copy/push, project-tag/release publication and journal-save branches. Counts
are conservative attempts or leaf invocations; a positive count does not prove
a remote write occurred. XO tag reconciliation records both its leaf invocation
and whether the before/after official pins require a tag. An unchanged pin pair
retains the existing leaf's explicit no-tag route and live authority check.

For a verified no-op, require a retained packet source, zero closure fetches,
zero cache publication invocations, zero OCI copy/push attempts, zero journal
saves, and no required tag/release operation. Read back current destination
identities as well. Journal equality alone cannot rule out repairing an absent
OCI object to its original identity. These observations exclude setup tools,
metadata reads, registry login and diagnostic artifact uploads, and do not
measure network bytes or establish a production percentage saving. A failed
run removes any stale success artifact and produces no successful result.
