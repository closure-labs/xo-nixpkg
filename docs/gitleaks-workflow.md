# Conventional repository secret scanning

The user-approved policy requires incoming-change scans for merges and releases.
The exact `Repository security audit` job is a real GitHub Actions job on
`pull_request` and `merge_group`, retaining required source Actions15368.
Historical scanning is a separate daily/manual audit: failures stay visible and
unresolved, but are not release blockers. This does not certify old history clean.

## Maintained sources and adaptations

The small read-only PR/merge-group layout follows AWS's maintained example:
https://github.com/aws-samples/sample-autonomous-cloud-coding-agents/blob/main/.github/workflows/security-pr.yml
Only its checkout/event-range/CLI pattern is adapted; not its other scanners,
permissive fallback, tool manager or reporting framework.

The upstream MIT CLI documents `gitleaks git --log-opts`:
https://github.com/gitleaks/gitleaks/tree/v8.30.1
We pin version8.30.1 and its official linux_x64 archive SHA256
`551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`.
No scanner is built on XPS. This is direct documented CLI use, not a claim that
we copied the upstream action workflow unchanged.

Reviewed wrappers were not used: official gitleaks-action v3 requires an
organization license key (described as free), while StepSecurity's MIT Node24
fork at ed9227474355f4d6faa6f94e9cd3f8320a311ba2 rejects merge_group and uses
`--no-merges --first-parent`. We do not fake events or fork either wrapper.

## Exact scope and safe output

PRs scan `base.sha..head.sha`; queue runs scan `base_sha..head_sha`.
All parents are traversed. `--diff-merges=first-parent` changes merge diff format,
not graph traversal, so side-branch commits and merge-only additions remain in
scope. Missing/shallow/unrelated refs, invalid events and wrong checkouts fail;
there is no full-history fallback. Diverged PR bases remain valid Git ranges.
Git's documented distinction is at https://git-scm.com/docs/git-log .

The protected-base `.gitleaks.toml` preserves all upstream rules and the existing
narrow canonical finding-identity exception, unchanged. No new exclusions,
fingerprints, baseline or size-based skipping are added. Inline allow-comments
are ignored. Git text diffs disable external diff/textconv execution. The scanner
reads candidate data; no candidate scripts, local actions, App credentials,
cache-write tokens or license secrets are used. Checksums and actions are pinned.

Scans use full redaction, no verbose output and no uploaded findings/report.
Scanner stdout/stderr are discarded; only fixed status and numeric exit code are
printed. Findings, runtime errors and the600-second wall limit all fail closed.

## Release binding and unresolved history

The existing `repositorySecretPolicy` binding now covers native publication
policy plus exact scanner workflow/config hashes. Old policy products cannot be
rescanned into this identity; fresh qualification and human review are required.
Every publication boundary queries ordinary GitHub metadata for the exact source's
successful merge-group run and current attempt, the real Actions15368 audit job,
its exact base/head range, and matching workflow/protected configuration bytes.
No synthetic check, custom receipt service or saved-success fallback is added.
Native scanning/push protection settings and the fresh repository-wide zero-open
alert publication observation remain unchanged, as do Grype inventories, accepted
vulnerability decisions, immutable outputs, attestations and signer authority.

The history audit fetches branch, tag and pull-request refs and scans all reachable
history in that snapshot. The known large historical JSON timeout is unresolved;
changing the wrapper does not fix it. A timeout is an audit failure, never clean
history. No prior failed audit is deleted, suppressed or grandfathered into success.
The explicit approved policy makes this historical debt nonblocking for releases;
it does not waive incoming scans or native publication checks.

This draft authorizes no settings window, merge, approval, cleanup or release
restart. Hosted CI must validate the actual pinned CLI/toolchain. Local tests use
small Git graphs and a mock CLI to check range and failure wiring; they do not
claim a local engine scan or successful full-history audit.
