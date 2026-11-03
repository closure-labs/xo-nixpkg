# Shared scanner setup rollout

The new composite action is the single installer for read-only scanner fixtures
and the diagnostic triage workflow. Both use the same upstream 8.30.1 archive,
checksum, HTTPS restriction, 60-second download limit and exact version check.
The action returns an explicit binary path; it does not modify the runner PATH.
GitHub documents composite actions as the standard way to share repeated steps:
https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action

The required incoming scan intentionally retains its existing inline installer
in this first stage. Its protected-base checkout does not contain the new action
until this PR is reviewed and merged. Running the proposed installer from the
candidate checkout would let that candidate replace the scanner with a passing
stub; this PR does not do that. Candidate policy fixtures remain separate,
read-only tests and do not certify the authoritative scan.

After this foundation reaches protected main, a follow-up can make the required
scanner checkout the action from the exact event base and use that copy. That
follow-up must bind the installer bytes in both policy-hash implementations and
the publication's source verification, update the reviewed policy hash, and run
fresh qualification. Existing proof must not be relabeled as the new policy.
The first stage removes one of three duplicate installer bodies. It does not
remove scanner invocations or claim runtime savings: each independent runner
still needs its scanner, and each meaningful scan/fixture remains.
