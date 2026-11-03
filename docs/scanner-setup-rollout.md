# Shared scanner setup rollout

The new composite action is the single installer for read-only scanner fixtures
and the diagnostic triage workflow. Both use the same upstream 8.30.1 archive,
checksum, HTTPS restriction, 60-second download limit and exact version check.
The action returns an explicit binary path; it does not modify the runner PATH.
GitHub documents composite actions as the standard way to share repeated steps:
https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action

The required incoming scan uses that same installer from its exact event-base
checkout (`controller/.github/actions/setup-gitleaks`). It never loads the
candidate's action, even when a PR edits the installer. The checksum and version
remain pinned in the shared action. Candidate fixtures use their proposed action
in separate read-only jobs and cannot certify the required scan.

The installer bytes are part of both policy-hash implementations and the
publication source verification. Publication fetches the installer at the exact
scan base, not the candidate head, and fails closed on a mismatch. This rollout
changes the policy binding and therefore needs fresh qualification; old evidence
is not relabeled. Required job name, App owner, ranges, redaction, timeouts and
failure behavior remain unchanged. All three installer copies now share one
body. Scanner invocations remain separate because they serve different purposes.

## Current validator compatibility

GitHub's newer native `$/` references executed successfully in hosted fixture
run 41585376609. The pinned actionlint 1.7.12 nevertheless rejects that syntax
before tests, as seen in preflight job 125749969813. Until the normal toolchain
update supports it, these two callers use GitHub's supported workspace-relative
`./` form and narrowly document the corresponding Zizmor style exception.
Neither caller has App credentials, write permission or signing authority;
checkout persists no credentials. The authoritative caller deliberately retains
its protected-base workspace path: native `$/` would select the workflow
revision instead of that separate trusted checkout.

Follow-up: migrate these two calls to `$/` and remove the annotations when the
validator supports it. Do not mechanically convert protected-base controller
actions: `$/` resolves the workflow revision, not a separately checked-out base.
Source: https://github.blog/changelog/2026-07-30-reference-same-repository-actions-with-self-repository-syntax/
