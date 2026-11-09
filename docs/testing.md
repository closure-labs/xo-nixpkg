<!-- SPDX-License-Identifier: Apache-2.0 -->
# Testing Guide

## Local Checks

```bash
# Evaluate all outputs (no builds)
nix flake check --all-systems --no-build

# Build every XO channel
nix build .#latest .#stable .#rolling

# Build and inspect the cacheable supply assertion for latest
nix build .#supply-protector-latest
jq .subject result/assertion.json
sha256sum --check --strict result/SHA256SUMS

# Validate the source-locked libvhdi package and FUSE3 linkage
nix eval --raw .#packages.x86_64-linux.libvhdi.name
nix eval --raw .#packages.x86_64-linux.libvhdi.fuseBackend
nix build --no-link .#libvhdi

# Inspect or run the exact independent attribute-build plan used by CI
nix eval --json .#lib.ciPlans.x86_64-linux.validation
nix run .#run-ci-plan -- \
  --plan lib.ciPlans.x86_64-linux.validation

# Inspect the schema-v2 classifier contract and its local lifecycle output
nix eval --json .#lib.ciClassifier
nix run .#classify-ci

# Build the reusable packaged automation closure
nix build --no-link .#automation-runtime
```

## Runtime Smoke Tests

### xen-orchestra-ce

```bash
nix build .#xen-orchestra-ce
./result/bin/xo-server --help
./result/bin/xo-server --version || true
```

### libvhdi

```bash
nix eval --raw .#packages.x86_64-linux.libvhdi.name
nix eval --raw .#packages.x86_64-linux.libvhdi.fuseBackend
nix build --no-link .#libvhdi
```

## Submission-Oriented Checks

Before opening nixpkgs PRs:

```bash
# Evaluate current flake
nix flake check --all-systems --no-build

# Optional: dry-run package build planning
nix build .#latest .#stable .#rolling --dry-run
nix build --no-link .#libvhdi
```

## Common Failures

### Yarn Hash Mismatch

If `yarnOfflineCache` hash mismatches:

```bash
./scripts/update.sh --release
```

### Source Hash Mismatch

If the XO source hash needs refreshing:

```bash
nix run .#update-xo-release
```

### Broken Symlinks in Output

The package currently removes broken symlinks during `preFixup`:

```nix
preFixup = ''
  find "$out/libexec/xen-orchestra" -xtype l -delete || true
'';
```

## CI Coverage

`ci/classifier.json` is the schema-v2 hosted-CI target graph exported as
`lib.ciClassifier`; `lib.ciPlans` is the reusable pure plan API. The classifier
emits one schema-v2 lifecycle document containing the exact validation and
publication plans. Workflow conditions, the lightweight gate, `nix run .#ci`,
and `nix run .#publish` consume that document directly.

Classifier fixtures cover documentation-only changes, component target
selection, dependency expansion, exact and ancestral merge-group reuse,
publication deltas, non-ancestral fail-safe behavior, and full manual runs.
The plan runner validates a supplied JSON plan without evaluating the plan a
second time, then builds each selected attribute independently so every
failure is collected. For local use, `.#ci` classifies the local event as a
full run when no prepared output is supplied. CI checks:

- independent package builds for `latest`, `stable`, and `rolling`
- reproducible closure assertions and SPDX/CycloneDX documents for every XO
  channel
- upstream/install checks and exclusive FUSE3 linkage for `libvhdi`
- XO `fuse-native` libfuse2 linkage and absence of bundled/prebuilt FUSE files
- updater, trusted-queue, schema-v2 runtime, shell, and ruleset fixtures
- immutable XO package-tag fixtures covering version normalization, channel
  no-ops, idempotency, conflicts, ancestry, and gated-checkout validation
- merge-queue credential preflight and permission-denial diagnostics
- transient update-branch push retry without pull-request mutation after a
  persistent failure
- cache configuration consistency and `automation-runtime` selection
- file-backed release discovery above process argument limits and publication
  manifests with arbitrary positive output counts
- closure-composition checks for packaged child commands
- `nix flake check`
- basic binary execution smoke tests

`nix flake check` is the canonical aggregate check graph; there is no separate
shell test aggregator. `nix run .#ci` is the supported end-to-end entrypoint
that evaluates the flake and executes every validation-plan target.

## Merge-queue acceptance

Create `MERGE_QUEUE_TOKEN` from a fine-grained PAT owned by an authorized
automation identity and restricted to `closure-labs/xo-nixpkg`. Grant Actions,
Contents, and Pull requests read/write repository permissions. The queue
workflow deliberately has no built-in-token fallback, and its credential
preflight runs before checkout or Nix installation. `CACHIX_CACHE_NAME` is not
used; only `CACHIX_AUTH_TOKEN` remains necessary for publication.

After installing or rotating the token, manually dispatch `Queue trusted
automation updates`. For PR #32 acceptance, verify that the workflow validates
its exact head SHA, approves any action-required pull-request CI, enrolls the PR
in the merge queue, observes a successful merge-group `CI gate`, and completes
protected-main publication. The following scheduled automation run should
substitute `automation-runtime` without cache-trust or credential warnings.

CI/security changes are validated through `devenv tasks run ci:repository-audit`.
Run `devenv tasks run ci:security-lint` for actionlint, zizmor, Gitleaks history
scanning, and inventory/journal fixtures. `tests/publication-boundary.sh` proves
all distribution leaves stop before external effects when live authority fails.
Use `devenv tasks run security:readiness` with repository-scoped runtime read
credentials to audit the live App/ruleset/baseline configuration before activation.

### Public consumer target selection

The public-cache probe selects one product identity using the newest qualification
run/attempt in the protected release ledger, before filtering disposition or
publication availability. This means newest qualification, not newest source
commit. Tied distinct identities fail. The complete supersession graph and merged
proposal provenance are then checked for that exact identity; an ambiguous,
revoked, rejected, or unpublished current target never falls back to older bytes.
Unrelated historical product conflicts remain unresolved and do not confer approval.

The selected product must have matching completed cache and handoff receipts in
its immutable, content-addressed publication journal. Those receipts are selection
evidence, not authorization or a substitute for downloading and verifying public
bytes/signatures. Cache receipts can remain valid for unchanged immutable outputs;
no new scan-freshness claim is made. Main and journal refs are checked before and
after the disposable-store probe, and changes fail without a success result.
This read-only check retains historical merged provenance semantics; it does not
renew live review authority or change any publication gate.

### Publication latency diagnostics

The existing `xo-publication-result` artifact also retains
`publication-fetch-source.json`. Its fixed status distinguishes an exact retained
packet from `no-exact-packet`, ambiguous packets, and validation failure. Discovery,
metadata materialization, and total lookup durations explain the metadata-first
path without exposing packet references or raw errors. No exact packet still uses
the existing artifact fallback; a different qualification run/attempt is never a
substitute, even if its immutable product is unchanged.

`publication-result.json` records disjoint monotonic `phaseMilliseconds` and total
`elapsedMilliseconds`, including the failed phase on an incomplete run. Cache and
handoff times include their live checks and journal checkpoints. Release-only
phases are absent for rolling publication. These times cover the controller, not
the preceding evidence-fetch workflow step or Nix startup.

The existing `authority-api-requests.jsonl` adds total gate `elapsedMilliseconds`
and time spent inside its counted live API callback (`apiMilliseconds`). Those
observations are nested within controller phase times and must not be added to
them. They do not measure every HTTP request, such as verifier subprocess traffic.
No timing, count, or source diagnostic supplies authority or skips verification.
All diagnostics use fixed fields and omit endpoints, bodies, credentials, and
arbitrary exception text. Run the fixtures with:

```bash
python3 -m unittest discover -s tests -p 'test_publication*.py'
PYTHONPATH=ci/decisions python3 -m unittest discover -s tests/decisions -p 'test_authority_request_counts.py'
```
