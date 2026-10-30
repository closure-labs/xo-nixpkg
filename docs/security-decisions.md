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

Both `rolling` and `release` publication require a separate accepted
`release-product` decision for the exact product document. A source review or
accepted risk scope cannot substitute for that decision. The gate checks the
product's current human review again before completing admission; publication
purpose only selects distribution behavior. The existing reconciler prepares
product proposals before scheduling admitted publication.

`security-reconcile.yml` retains evidence in `ghcr.io/closure-labs/xo-nixpkg-decisions`
and opens content-addressed bot proposal PRs. It reconciles retained candidates
hourly for the latest successful main qualification, requests a refreshed scan when
health expires, and dispatches publication after live approval. An optional
`qualification_run` input explicitly selects an older successful product; older
approvals no longer automatically resurrect historical publications each hour.
Daily qualification refreshes the most recent retained product
without changing its product document or release approval identity. A manually
requested new qualification builds current main; `qualification_run` instead
refreshes an existing exact product with the current trusted scanner.

Refresh and publication requests carry the qualification run and attempt. Stable
workflow run names let the serialized reconciler avoid duplicate active requests.
It also skips a successful release publication for that exact requested attempt
while the selected scan remains fresh. A rerun or rescan has a new attempt or run
identity and needs its own handoff; a matching product hash alone never suppresses
fresh publication. Failed lookups stop scheduling rather than imply an empty queue.
The bounded lookup considers up to 1,000 dispatches created since the selected
qualification run began; reaching that bound without a match stops scheduling
with an explicit recovery diagnostic. Failed producer completions do not wake the
expensive reconciliation job. A tick downloads at most one complete product packet,
instead of replaying up to 20 historical packets.

## Publication and recovery

`publish.yml` downloads data from a successful completed producer and runs trusted
main controller code. The live gate protects all eight public cache roots, tags,
GitHub releases, and downstream handoffs. The publisher substitutes exact output
paths and checks their NAR hashes; it never builds candidate derivations.

For explicit repair or recovery, dispatch `publish.yml` with `qualification_run`
and `purpose`. Optional `qualification_attempt` rejects a race with a newer rerun;
omitting it resolves the current successful attempt. This direct path always
revalidates authority and remote state, even if scheduled reconciliation found a
previous successful publication. Downloaded `scans.json` must identify the requested
run and resolved attempt before either refresh or publication admission.

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

## Automatic CI admission for trusted authors

The `Admit trusted pull request CI` workflow approves pending GitHub Actions
execution for both draft and ready PRs authored by `cl-decider[bot]` (pinned
numeric account ID) or a currently active member of the pinned closure-labs
Super Admins team with repository maintain/admin permission. The initiating and
rerun actors must also satisfy that identity policy. An unrelated actor cannot
borrow a trusted author's PR to obtain automatic execution approval.

The protected-main controller reads `ci-admission-policy.json`, authenticates
the repository, allowlisted CI workflow, current open PR head and source
repository, then rereads identity and run/PR bindings immediately before the
run-approval endpoint. It never checks out candidate code, downloads candidate
artifacts, posts PR reviews, dispatches privileged candidate workflows or
requests a merge. Draft-to-ready transitions do not require a review to run CI.
Workflow events handle pending runs; a fifteen-minute scheduled reconciliation
also covers missed events and runs whose approval state appeared later.

Other contributors retain GitHub's existing external-contributor workflow
approval requirement. Missing identity visibility, revoked membership or
permissions, moved heads, changed run attempts and transport failures fail
closed. Ambiguous approval writes are not retried without fresh readback and
identity checks. Human exact-head merge and publication authority are unchanged.

Official same-repository Dependabot Actions updates have a separate narrow
[admission contract](dependabot-admission.md): complete immutable Actions-pin or paired-lock verification and read-only job
validation admit execution without prior review. Exact-head human review remains
mandatory for merge. This does not broaden other author or release policies.

GitHub's [run approval API](https://docs.github.com/en/rest/actions/workflow-runs#approve-a-workflow-run-for-a-fork-pull-request)
approves CI execution only. The App token has Actions write, contents and PR
read, and organization members read; it has no PR-review or contents write grant.
