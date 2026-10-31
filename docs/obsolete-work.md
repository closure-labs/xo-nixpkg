# Obsolete workflow events and policy transitions

An old decision-event collector may complete after its ephemeral merge-queue ref
has disappeared or changed. The controller reads the bounded current matching-ref
inventory for that exact PR. A valid complete inventory that no longer contains
the event SHA produces no worker and no check. Malformed inventory, overflow,
foreign refs and API failures (including 404) still fail closed. This outcome is
not audit success or an approval and cannot replace a current required check.

This patch deliberately leaves policy-incompatible retained-product rescans
blocked. Skipping those as successful qualification would confuse latest-success
selection and evidence promotion. A follow-up needs an explicit authenticated
ineligible-product result that all qualification/reconciliation selectors respect,
or a separate rescan workflow identity. Neither fallback nor automatic rebuild is
introduced here. Until that integration is reviewed, use a fresh protected-main
qualification after a policy change; do not retry the incompatible rescan.
