# Controller wakeups

Normal CI execution admission is event-driven: a held validation/scanner run or
a submitted/edited/dismissed review wakes the protected admission controller.
Merge approval completion no longer repeats the same admission inventory after
the review collector already woke it. The hourly schedule remains a fallback
for missed events, delayed GitHub approval state, and App-created activity;
manual dispatch remains available. Recovery can now take up to roughly one hour
plus GitHub schedule delay instead of roughly fifteen minutes plus delay.

That changes recovery latency, not who may execute or merge code. The controller
still rechecks its complete identity, exact-head and unprivileged-file contracts.
The hourly fallback reduces nominal scheduled admission runs from 96 to 24 per day
(72 fewer runner/Nix/App-token startups). Actual event-volume savings depend on
repository activity; no timing or API-count improvement is claimed yet.

Update producers no longer start the queue controller before their new PRs have
finished validation. Validation, merge authority, the existing review relay,
daily recovery and manual dispatch still wake queue reconciliation. Release
reconciliation retains qualification completion, merge approval completion,
decision-file pushes, hourly recovery and manual dispatch: approval can enable a
proposal's native queue progression before its decision is merged.

No global Actions approval setting, repository rule, review requirement,
membership check, findings acceptance, provenance or publication gate changes.
