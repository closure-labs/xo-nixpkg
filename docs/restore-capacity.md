# One-time retained restore capacity check

This diagnostic is not a publisher or admission check. It cannot authorize a
release. It runs once on opening the same-repository diagnostic/restore-capacity
PR; later synchronizations do not repeat the multi-gigabyte experiment.

Fixed inputs are qualification 41955054111 attempt 1, product
16f2a292627931c06ad1241c6d7f274efa1eb423b6752637c01ec363ae1745b7,
and #274's digest-bound private packet. Source checkout is the immutable reviewed
#276 revision 9c001f4c6a3588f0c654436a337136ad038e34e2, with the restore file's
SHA-256 independently checked. The workflow carries only read permissions and no
App key, Cachix token, signing credential or publication credentials.

The same publisher/fetch/devenv tool derivations are realized first, without
executing the publication commands or building distributed products. Native
producer and attestation verification, product/asset digests, packet/part/archive
hashes, member guards, exact root NAR hashes and recursive verification remain.
Historical observation authentication is not a claim of fresh findings or live
publication authority. Existing target roots cause an inconclusive/blocked test.

The actual job-cache hard-link/materialization path is preserved. Its inode
sharing is measured. Original authenticated parts remain intact. #276 deletes
only the verified reassembled tar before the local import. An artifact ZIP's
2,745,497,866-byte size is not substituted for transport archiveSize.

A 2 GiB physically allocated reserve file is held throughout the experiment and
is not available to imports. A sampler also stops at 512 MiB remaining outside
that reserve. Reported free-byte measurements explicitly exclude the held
reserve; add it back only when comparing total capacity budgets. The reserve is
removed by final private-work cleanup. All paths must share the same filesystem.

To cap the actual importer rather than just its RPC client, Nix daemons are
stopped on the disposable runner and root direct-local-store mode is used under
one systemd cgroup: 2 CPU, 4 GiB physical RAM, no swap, 2100-second hard wall.
The installer Nix engine performs local store writes; the normal pinned client
closure is still realized to preserve bootstrap disk demand. This changes the
RPC arrangement, not the target filesystem or NAR format, and is reported as
localStoreMode. No existing cache object is overwritten and no retrieved package
binary, service or script is executed. The only Nix import commands are copy
from the authenticated local file cache, path-info and recursive store verify.

Normal setup can fetch trusted tool dependencies. Actual retained inputs are
limited to 4 GiB, bounded metadata/member sizes and a 24 GiB logical NAR union.
Read credentials and registry auth are removed before importing. Any denied
read, cap failure, identity mismatch, timeout, output overflow or low-space event
blocks without retries or alternate credentials. Only fixed-schema numeric and
identity observations are uploaded; raw scan reports, archive contents and
registry auth remain private and are cleaned up.

A pass requires all eight roots restored with exact verified NAR identities,
recursive verification and the reserve intact. A pass is capacity evidence for
this fixed input and bootstrap, not permission to retry publication or a timing
speedup claim. The earlier canceled publisher's uncheckpointed cache state must
still be reconciled separately before any guarded rolling delivery.
