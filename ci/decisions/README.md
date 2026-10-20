# Human decision leaves

These commands adapt Finite's `decision-authority.py`, `decision-check.py`,
`security_decisions.py`, and `decision_packets.py`. Their original authority,
normalization, hostile-packet and merge-queue fixtures are retained under
`tests/decisions` alongside adaptation tests. Python's standard library, `gh`
and `oras` are the only runtime dependencies.

Every command accepts `--config POLICY.json` and optional `--output FILE`.
Policy declares `schema: 1`, `enabled`, `repository`, `botLogin`, positive
`appId`, `profiles`, `policyPath`, `producerWorkflows`, and optional
`requiredAuthorityCheck` (default `Maintainer decision authority`). The ledger
root is `automation/decisions`. Production gates authenticate the local policy
against current main, fail while disabled, and require the effective main rule
to bind the authority check to the configured App integration ID.

## Inputs

`scans.json` contains `schema: 1`, `repository`, immutable product `revision`,
`producer: {workflow, runId, runAttempt, revision?}`, UTC `scannedAt` and
`expiresAt` (at most 48 hours apart), and `profiles: {profile: nativeScan}`.
Producer revision defaults to product revision. A current-main producer can
rescan retained historical inputs; the product source must be its ancestor.
Each native scan requires complete observations, healthy scanner status and
`subjects: [{storePath, narHash}]` covering every distributed closure root.
Original native reports, inventory and source applicability evidence belong in
the retained packet directory. Scan adapters must verify database freshness,
complete native/npm coverage, inventory bindings and exact source fixes before
declaring native health. The decision core does not recreate a missing scanner.

Observations use Finite's versioned `component` package URL, advisory/aliases,
severity, exploitation/CVSS evidence, complete absolute shipped `locations` and
fix versions. Optional `exposureBindings: [{location, outputName, relativePath}]`
bind every shipped file exactly once to the actual derivation output. The
authenticated native producer validates those roots against inventory. Risk
comparison uses the output name and relative path, retaining raw store paths in
native evidence, so a rebuilt hash alone does not expand exposure.

`product.json` contains `schema: 1`, `repository`, source `revision`,
`products: {profile: {storePath, narHash}}`, and
`assets: {safeFilename: sha256Hex}`. Optional
`roots: {name: {storePath, narHash, profile}}` binds auxiliary distribution
roots, which must also appear in authenticated native scan subjects. The whole
canonical document is the official release identity. Keep producer run IDs and
scan timestamps out of this document. Both documents need verified GitHub
provenance from an allowlisted producer workflow on main; the producer must have
completed successfully before a controller consumes it.

## Commands

- `authority.py --proposal FILE [--pr N --allow-open --queued-proposal FILE]`
  verifies exact-head live Super Admin authority. Open authority is premerge
  only. Runtime authorization derives merged origin and current main ancestry.
- `check.py --collector-run ID` resolves PR/queue targets from GitHub metadata
  for `.github/workflows/decision-events.yml`, validates proposal packets and
  governed changes, and posts the required check with the scoped App token.
  Merge queues must contain one PR per group.
- `reconcile.py --kind security-findings|release-product --scans FILE
  [--product FILE] --directory DIR [--rationale TEXT --disposition accepted|rejected]`
  authenticates complete native evidence, stores the entire directory as a
  digest-addressed OCI packet and creates a bounded App-authored proposal PR.
  Official approval packets must retain the actual hashed release assets.
  This command can prepare baselines while publication is disabled.
- `reconcile.py --kind security-revocation --decision-hash HASH --rationale TEXT`
  proposes withdrawal of the exact current accepted scope without fresh scans.
- `proposal.py --kind KIND --payload FILE --output FILE` only renders a
  proposal. Rendering or merging self-reported JSON grants no authority.
- `admission.py --scans FILE` and `publication.py --scans FILE --product FILE
  --purpose rolling|release` authenticate current native health and admission.
  Official releases additionally require approval of that exact product.
  Call publication immediately before each external distribution side effect.
- `readiness.py` validates enabled live policy, the App-bound main rule and
  the initial accepted baseline. This is an activation preflight, not a
  replacement for publication's candidate-specific native-health checks.
- `recovery.py --journal FILE --product FILE --scans FILE` checks the exact
  immutable journal identity and repeats the ordinary live release gate.
  Publishers must independently compare each existing remote asset/tag/cache
  identity and persist their journal with concurrency/CAS protection. The core
  neither records a successful remote write nor authorizes one from a journal.
- `handoff.py --handoff FILE --directory DIR --expected-revision SHA
  --expected-channel PROFILE --expected-store-path PATH --expected-nar-hash SRI`
  requires the checked upstream XO policy, verifies the attested handoff plus
  retained original documents, checks the independently resolved locked output
  and repeats current upstream admission. Downstream appliance admission remains
  a separate gate.

Exit status 0 means the requested check/action completed. Exit status 2 fails
closed and emits a bounded JSON error. No receipt, transport timestamp, label,
AI assessment or old signature substitutes for current GitHub authority.

No live service is needed to run the fixture suite:

```console
python3 -m unittest discover -s tests/decisions -q
```
