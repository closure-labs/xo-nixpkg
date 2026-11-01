# Inventory-only vulnerability refresh

A refresh scans the exact authenticated product SBOMs against a newly prepared
Grype database. It does not need package binaries in the local Nix store.

Full qualification still builds/realizes all eight distributed roots, generates
four complete inventories, scans them, exports the same NAR transport and attests
the same product/scans/handoff subjects. It additionally uploads a native Actions
`qualified-inventories-RUN-ATTEMPT` artifact containing `product.json`, `scans.json`
and the flat immutable assets named by the signed product manifest. This is data,
not a new authority receipt. Repository/workflow/source/run/attempt and original
product attestations are still verified by the existing fetch/rescan verifier.

Scheduled/manual refresh fetches this inventory artifact, not `qualified-products`.
Only explicit absence/expiry may use the existing private retained packet reader;
it reads bounded metadata and named inventory layers, never closure layers. API
errors, incomplete artifact lists, duplicate names, malformed/oversized metadata,
failed downloads or failed authenticity checks stop. Members must be regular and
match the exact signed asset set and SHA256 hashes (16 MiB product, 128 MiB scans,
64 MiB per inventory asset, 512 MiB aggregate). Unknown/absent assets fail closed.

The unchanged protected scanner receives the same runtime CDX bytes, fresh DB
snapshot and normalization path. Subjects retain the original store paths/NARs,
auxiliary roots, profile applicability and original product producer. Refresh does
not run Nix realization, regenerate inventory, export transport, or copy old raw
reports/success envelopes into new evidence. New scans have new producer/time/DB
identity and retain the original authenticated transport manifest. Old-policy
products still require new qualification; no policy/hash/approval change is made.

Publication retains all live admission and destination checks. A full historical
packet works as before. When a lightweight refresh needs closures, the existing
fetch/verifier resolves the original product producer's exact run and attempt,
including retained recovery, and requires byte-identical product plus identical
transport manifest. It validates part hashes, installs those bytes once and uses
the existing archive/import/recursive NAR verification before cache publication.
A missing/changed original transport blocks; no build or cache overwrite fallback
is added. Partial local transports are not silently repaired.

Public handoffs remain self-contained. Lightweight private packets are not copied
to public as incomplete substitutes: publication materializes original transport
once and uses the existing authenticated handoff push/readback. If public cache
already matches, it materializes transport for that handoff without importing NARs.
Full packets retain their existing server-side handoff-copy path. Consumer release
identity/supersession selection, signing, provenance and authority are unchanged.

## Validation and measurement

Local tests use tiny synthetic assets, mocked transport/proof/Grype responses and
the real normalizer/packet member hashing. They establish wiring and semantic
findings equality for identical inputs, not a live scanner/cryptographic proof.
No local Nix build/evaluation/scanner or closure download is part of this change.
Hosted PR CI validates the complete pinned fixture/toolchain integration.

After normal human review/merge, use the automatic full qualification to create
the first native inventory artifact. Then compare one ordinary scheduled refresh:

* baseline run 41303769844 fetched in185 seconds and restored/rescanned in235;
  its qualified-products artifact was2,744,962,504 bytes;
* record new inventory artifact bytes and fetch/verification/scan times separately;
* confirm zero closure-part downloads/imports/realizations during refresh;
* compare exact retained runtime SBOM digests, all profile subjects, scanner flags
  and normalized observations using a fixed DB snapshot in hosted fixtures;
* confirm fresh DB/time identities, unchanged complete coverage, rejection of
  missing/tampered assets and failed proof/scan/DB checks;
* publication must fetch original transport at most once, retain all live gates,
  preserve the complete public handoff and verify all destination NAR identities.

Normal observations from different DB snapshots can legitimately differ; do not
claim cross-time findings equality or speedup from aggregate workflow timings.
The additional small native artifact is intentional duplication of inventory data
so periodic scans avoid transferring the much larger closure artifact. Publisher
may still transfer large original transport to preserve a complete public handoff.
