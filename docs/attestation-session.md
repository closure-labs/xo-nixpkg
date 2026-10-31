<!-- SPDX-License-Identifier: Apache-2.0 -->
# Publisher attestation material

Publication still repeats admission at consequential boundaries. The publisher
creates a private temporary session and removes it when that process exits. A
new publisher ignores an inherited session path. Child admission commands may
reuse signed bundles in that session; they never reuse a verification result,
review, membership decision, policy decision or destination receipt as authority.

The first verification uses the normal GitHub API lookup. Material is retained
only after successful cryptographic verification and exact subject-digest and
producer run/attempt matching in the verified statement. The key also binds the
complete policy, repository and owner IDs, source revision, signer workflow,
issuer, predicate, hosted-runner requirement, subject name/size and verifier
path/hash/arguments. Unsupported producer metadata keeps online verification.

Every hit invokes the same pinned `gh attestation verify` with `--bundle`, the
same identity/source/issuer/predicate/hosted-runner flags, and its current default
Sigstore trust-root handling. This is local cryptographic verification, not a
stored passing verdict. Subject and verifier bytes are checked before and after.
Live repository and owner IDs are also checked before and after: upstream warns
that local bundles alone cannot detect repository-name reassignment.

All existing current-main, complete-ledger, exact-product, human review,
membership, required-rule, evidence-age, native-posture and remote-destination
checks remain in place. A warm bundle cannot satisfy any of them. Verification
failures invalidate that material. Session files are private, regular, bounded
and digest checked; raw bundles are not uploaded as CI artifacts or logged.

## Measurement and limits

Before this change, failed publication 41225385395 recorded seven successful
304-call authority callbacks and a four-call blocked callback: 2,132 logical
authority API calls. Recovery 41228851442 recorded eleven successful callbacks:
3,344 calls. Those counters exclude `gh attestation verify` internal traffic and
may undercount transport retries. Existing Git-blob reuse already fetched only
54 unique blobs per job.

With the single configured qualification signer, each successful full gate
invokes the verifier for scans and product: 22 verifier invocations across the
eleven successful recovery gates. The new design retains all 22 verifications
but can reuse each matching subject's downloaded material after its first use.
Default trust-root refresh and live repository-ID reads still occur. No claim of
zero network traffic or measured production speedup is made. The 304-call live
authority path is unchanged; its separate optimization needs separate review.

Version-only qualification 41218442574 took 8m20s overall; its combined runtime
inventory/build/fresh-scan step took 7m25s. Four primary roots and three
supply-protector roots retained their exact paths and NAR hashes. The automation
runtime acquired a 0.10.2 store path with the same NAR hash. A fresh version-bound
product and scan were required; these timings do not establish that unchanged
XO roots were recompiled instead of substituted.

Upstream reference: https://cli.github.com/manual/gh_attestation_verify .
