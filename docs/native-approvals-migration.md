# Native approval cutover

The migration replaces custom security/product decision graphs with native
GitHub PR reviews for both code and releases. It does not accept the historical
finding ledger or publish a product during installation.

## Prepare, review, activate

1. Run `python ci/configure-native-approvals.py prepare` with repository
   administration access. This backs up the existing rules/environment, enables
   one approving review, CODEOWNERS, stale-review dismissal and approval after
   the last push, and disables environment administrator bypass. It preserves
   all required checks, including the legacy App check, and sets
   `NATIVE_RELEASE_APPROVALS_ENABLED=false`.
2. Review and merge the source migration through the existing required checks
   and native review rules. The source includes `.github/CODEOWNERS`, the shared
   native validators, release proposal and publisher workflows, and disabled
   legacy policy. There is no pre-approved release request in this change.
3. From the merged checkout run
   `python ci/configure-native-approvals.py activate`. The script first verifies
   the policy and CODEOWNERS on protected main, absence of retired controllers,
   exact merged native workflow bytes and effective native protections. It then
   removes only `Maintainer decision authority` owned by App 5384448 from the
   required checks and enables release proposal automation. Other status checks,
   integrations, merge queue limits and empty bypass lists remain intact.
4. Run the effective policy audit. Dispatch a fresh qualification or wait for
   the next successful main qualification. Review the resulting native release
   PR before allowing any public publication.

Each phase writes a backup under `/tmp/xo-native-approval-migration`. Use
`--backup-dir` with a new directory for an intentional repeat; existing backups
are never overwritten. The `check` phase performs only validation.

The source migration temporarily freezes the old publisher until activation;
it does not introduce an interval with no approval requirement. If activation
is delayed, native proposals remain disabled. Existing historical decision
records are preserved, and no human review or deployment is approved by the
migration script.

## Semantics that change

- A native approved-and-merged release request replaces both security scope
  decisions and exact-product decisions. Each new scan/product needs a review.
- Review comments such as `/decider approve` are not native approvals.
- Native GitHub rules enforce reviewer ownership, stale dismissal and queue
  admission; the publisher does not implement a second reviewer-selection API.
- Withdrawal uses a reviewed change to the current request or policy, plus
  cancellation of pending work. Historical merged reviews do not act as a
  mutable custom revocation ledger.
- The existing publication environment retains branch restrictions and secret
  isolation, with no second human approval prompt.

GitHub documents the relevant [native review protections](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
and [environment branch and secret restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).
