# Native approval cutover

CodeQL's native PR finding rule blocks errors and High/Critical security alerts,
in addition to requiring the language analysis jobs to complete. The shared
protection validator checks those thresholds and preserves stricter settings.
GitHub [does not apply this finding rule to merge queue groups](https://docs.github.com/en/code-security/concepts/code-scanning/merge-protection).
Queued candidates require all three language analyses. Each required language
job now also runs the shared `codeql_findings` validator after upload processing.
It binds the upload to the exact merge candidate, run/attempt and language, then
compares authenticated SARIF with the analysis of that group's exact protected
base. New errors or High/Critical security findings block the job. Stable GitHub
alert identities distinguish existing findings from new ones; equal counts are
insufficient. Missing analyses, unhealthy extraction, absent rule metadata and
incomplete results block validation. If the protected-base analysis is not yet
available, complete/rerun that main CodeQL analysis before retrying the queue.

GitHub's [REST ruleset response](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset)
omits bypass actors for read-only callers. When that field is absent, the shared
validator uses the same observer's permissions for a fixed GraphQL read query.
It requires the expected repository, active ruleset and an explicit zero bypass
count. Missing data, query errors and nonzero counts still block publication;
the observer does not need ruleset write access.

The same protection validator requires last-push approval and extra approval
for unattributed changes, as well as CODEOWNERS and stale-review dismissal.
The CI verdict requires output attestation when eligible; failure, cancellation
or an unexpected skip blocks `CI gate`.

Release proposal generation never rewrites an open native release review.
Identical retries keep its head; newer evidence is deferred until that PR is
merged or closed and another qualification proposes the next request. This
also avoids racing an approval arriving between an API read and branch update.
Expired or obsolete pending requests still fail publication freshness/policy
checks: close them to allow a fresh proposal; no review carries to new bytes.

Every successful publisher attempt triggers the existing read-only public
consumer probe, in addition to its periodic/manual checks. Shared native
validation authenticates both successful publisher jobs and protected-main
ancestry, then selects the request/policy at that immutable publisher revision.
The probe verifies completed journal receipts, downloads the exact roots into
an empty store and verifies recursive signatures and NAR hashes. A later main
commit does not redirect an event-triggered probe to a different product. Its
retained result records the publication run, attempt, revision and request hash.

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
