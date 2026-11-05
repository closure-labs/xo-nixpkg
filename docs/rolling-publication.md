# Rolling delivery and versioned releases

Automatic reconciliation dispatches `publish.yml` with `purpose=rolling`. This
publishes the complete approved product: latest, stable, rolling and libvhdi,
plus the approved supply-protector and automation-runtime roots. Only missing
cache objects are uploaded; exact NAR identity conflicts remain blocking. The
authenticated product packet is handed off to the public products registry.
“Rolling” is the delivery mode, not a filter selecting only `xo-rolling`.

Rolling delivery does not enter XO-tag, project-tag or GitHub-release stages.
Versioned publication remains an explicit manual `publish.yml` action with
`purpose=release`, after the required exact-product human approval and current
live admission. An approval of a product packet is not an instruction to run
versioned publication. The product record itself binds all roots and assets;
it does not encode a rolling/versioned purpose.

Scheduling recognizes an exact-run/attempt active or successful rolling or
release publication to avoid duplicate cache/handoff work. Fresh observations
are still required before historical success suppresses bulk work. Unknown
purposes, foreign workflows, other attempts and failed runs cannot authorize
publication. A failed release may be followed only by fresh gated rolling
delivery; no automatic release retry is introduced.

The existing manual publisher still offers rolling and release. This change
does not run either workflow, approve findings/product risk, change GitHub
settings, select a narrower profile set, alter the product or bypass provenance.
For tonight, the user requested rolling delivery only; a new versioned release
requires a separate explicit user request and all normal gates.
