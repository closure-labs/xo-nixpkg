# Security and release decisions

Only content-addressed proposals authenticated by the decision App and a current
`closure-labs/super-admins` human with repository maintain/admin access authorize
publication. Machine assessments and generated receipts cannot grant authority.

Publication is frozen by `ci/decision-policy.json` until coordinated bootstrap
validates the installed App identity, live rulesets and permissions, and this
repository has an independently approved complete security baseline.

## Product qualification and authority

`qualification.yml` builds every XO channel and standalone libvhdi without cache
or release credentials. The existing supply-protector assertions remain published.
Additional inventories bind installed npm package manifests and files to their
exact XO output, and every shipped ELF to its versioned derivation output.
Unversioned native code, missing derivations, incomplete npm coverage, failed
scanner probes, and stale databases fail qualification.

`scans.json`, the immutable `product.json`, and each `handoff-<profile>.json` are
attested by the successful qualification producer. The product identifies primary
and auxiliary Nix outputs by store path and NAR hash, plus deterministic inventory
asset hashes. Human decisions cover all severities and the complete profile set;
CVSS increases, exploitation, or expanded exposure require review. Stable relative
output/file exposure permits accepted risk to carry across unchanged paths.
Security decisions also bind each profile's runtime policy independently of its
findings. An empty report cannot authorize previously unreviewed exposure. The
shared validator understands Maestro's installer coverage contract and requires
all declared roots in both scanned subjects and retained products.

The protected controller verifies the current policy, exact proposal head,
App-origin check, current SuperAdmins membership, maintain/admin permissions,
review state, and merged ledger provenance. A generated report never substitutes
for authority. `automation/decisions/` contains only immutable canonical proposal
JSON under `security/` or `releases/`.

`security-reconcile.yml` retains evidence in `ghcr.io/closure-labs/xo-nixpkg-decisions`
and opens content-addressed bot proposal PRs. It reconciles retained candidates
hourly, requests a refreshed scan when health expires, and dispatches publication
after live approval. Daily qualification refreshes the most recent retained product
without changing its product document or release approval identity. A manually
requested new qualification builds current main; `qualification_run` instead
refreshes an existing exact product with the current trusted scanner.

## Publication and recovery

`publish.yml` downloads data from a successful completed producer and runs trusted
main controller code. The live gate protects all eight public cache roots, tags,
GitHub releases, and downstream handoffs. The publisher substitutes exact output
paths and checks their NAR hashes; it never builds candidate derivations.

Publication checkpoints use independent Git branches named
`automation/publication-<canonical-product-sha256>`. Each commit contains one
`journal.json`; non-forced fast-forward updates provide compare-and-swap behavior
between concurrent writers. Replays repeat live authority and compare immutable
remote tags/releases before writing. Cache writes are idempotent NAR uploads.
Handoff evidence is retained indefinitely in the digest-addressed
`ghcr.io/closure-labs/xo-nixpkg-products` package. The journal's `handoff` step
records the packet reference and digest; refreshed handoffs retain earlier packets.
Consumers independently verify the attestation, exact locked revision, channel,
store path, NAR hash, and current upstream admission.

A package/cache refresh does not create another project release when the same
project version has already been released. Project and XO version semantics stay
independent. The orchestrator does not deploy XCP-ng or bypass Maestro's own
qualification and release decisions.

## Coordinated activation

The checked policy and ruleset pin the installed `cl-decider` App ID `5384448`
and bot login `cl-decider[bot]`. Keep `enabled=false` while deploying both
repositories. The coordinator must freeze and drain old writers, verify the
repository-scoped App identity, install the App-bound ruleset, confirm all
required checks, and review the initial complete XO security baseline (including
empty findings). Activate XO first, then publish the admitted immutable handoff
needed for Maestro qualification. Keep Maestro publication frozen until its own
baseline and exact upstream handoff are reviewed; verify release recovery in
each repository before unfreezing its scheduled writers.
Configure the `publication` environment to allow only protected `main` before
granting its cache credential. The publisher uses one durable FIFO concurrency
group and rechecks admission before each distribution action.

The decision App (`DECIDER_CLIENT` / `DECIDER_KEY`) needs organization Members read and repository Administration read,
Contents/Pull requests access, Checks write for authority, and Actions write for
resumption. Mint only the per-job permission subset. Package retention applies to
both decision and product packages; disabling it invalidates readiness.
Credentials are declared in `secretspec.toml` and resolved only at runtime.
The repository Actions allowlist also permits the pinned
`step-security/harden-runner@dc2769abcc0fcfbadfc1df54081c1608579ef6b2`
used by CI, CodeQL, and the security audit. Keep verified-publisher blanket
access disabled and preserve the existing Determinate action entries.

The separate `SECAUDIT_CLIENTID` / `SECAUDIT_PEM` audit App has read-only
Administration access and never posts decisions, checks, or publication writes.
Its client ID and private key are inherited from organization settings. Policy
source metadata uses the built-in repository reader token; administration
queries use the audit App token, without adding Contents access to that App.
Queue jobs mint short-lived Decider App tokens rather than reading a stored
merge-queue token. The public `DECIDER_APP_ID` variable is repository-scoped.

Exact NAR closures travel between isolated producer and publisher jobs in a
private binary-cache archive split into digest-checked parts. The signed scan
manifest binds every part's digest and size. Publishers authenticate current
admission before parsing the archive, reject unsafe members, import only exact
approved roots without builders, and verify the imported NAR hashes.

Complete candidate packets, including NAR transport, remain in the private
`xo-nixpkg-decisions` package before admission. The registry layer checks package
visibility before and after upload and rejects public/internal packages or API
failures. Expired Actions artifacts fall back to digest-bound packets referenced
by merged decisions or pending bot proposals; consumers verify producer identity,
attestations and every file. The independently admitted `xo-nixpkg-products`
package carries downstream handoffs after publication.
