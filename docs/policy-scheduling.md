# Policy-aware evidence scheduling

Reconciliation distinguishes scheduling completion from qualifying evidence.
After authenticating scan producer provenance, scan attestation, product identity
and product attestation, it validates observation health/profile completeness and
both policy-binding schemas. Authenticated obsolete-policy evidence produces
`status: awaiting-current-evidence`, `action: wait`, `reason: obsolete-policy`,
`authorityClaim: false`, and `usableEvidence: false`. It cannot create proposals,
request a retained-product refresh, dispatch publication or satisfy admission.

The same classification covers retained metadata inspection and downloaded
Actions evidence. A successful scheduler run means work was classified, not that
qualification succeeded. No qualification run is relabeled or synthesized.
No successful candidate means awaiting qualification. Missing retained metadata
requires the existing authenticated Actions materialization path, not an empty
success. API failure, malformed/mismatched policy, unhealthy/incomplete evidence,
invalid provenance, signatures or output identity remain hard errors.

An operator can request the normal protected-main qualification with no retained
run input to create genuinely fresh evidence. This patch does not auto-dispatch
that expensive operation. An explicitly requested or daily direct retained rescan
of an obsolete-policy product still fails its existing qualification guard; it is
never green or automatically promoted. Reconciliation now waits instead of
repeatedly scheduling that known-ineligible refresh. Current-policy expired
observations retain the existing exact-producer refresh behavior.

Hosted validation must run policy scheduling, retained scheduler, evidence
transport, existing attestation/provenance and complete decision fixtures. No
local tests, builds or Nix evaluation were run during preparation. Publication
admission and fresh live native observation are unchanged.
