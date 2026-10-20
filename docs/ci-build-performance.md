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
base/head and merge parents. Queue caches bind their protected base to both the
source parent and exact queue ref. Manual producer runs must be on exact main.
Candidate workflow or controller changes require a new reviewed bootstrap.

Reusable payloads and receipts expire after seven days; timing metadata remains
for 30 days. Qualified release evidence retains its existing durable policy.
Actions artifact transport in this public repository is separate from the private
GHCR decision registry and from admitted public Cachix/release publication.

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

## Concurrency pilot

CI workflow dispatch accepts `build_jobs=1` or `2`; the default remains one.
The runner refills the first completed slot, preserves plan-ordered diagnostics,
runs every target on failure, and promotes result links only after full success.
Cancellation terminates its own build children. Cheap preflight remains serial.
Compare matched hosted runs for elapsed time, CPU/RAM/disk, artifact bytes and
reuse export/download/verification overhead before raising the default. A branch
benchmark cannot certify cache output until its producer workflow is reviewed.
