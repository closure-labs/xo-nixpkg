<!-- SPDX-License-Identifier: Apache-2.0 -->
# Automatic read-only Dependabot CI

Dependabot keeps its authorship and normal PR readiness. Execution does not require
human review. Merging still requires an eligible human's approval of the exact
current head, plus the existing required CI, security and maintainer-authority
checks. Release/security proposal authority and signing are unchanged.

The existing protected-main admission controller handles GitHub's pending native
execution approval. Repository policy remains `all_external_contributors`; there
is no blanket author exception, privileged candidate dispatch or global settings
change. The controller has its existing scoped Actions-write permission, reads
metadata and immutable blobs only, and makes at most one native approval request
for each freshly verified run. It never checks out or executes candidate code.

The current protected base must be an ancestor of the candidate head. Diverged
branches wait for refresh, so main-only changes cannot appear in an unaudited
synthetic merge tree. The base/head binding is reread before execution approval.

Supported same-repository updates from the official numeric Dependabot identity:

* Actions updates must pass the existing complete-tree, hash-verified pin-only
  classifier. Every changed `uses` SHA must match its exact upstream version tag;
  owners, action paths, workflow semantics and file modes cannot change.
* Nix updates may change only `flake.lock` and `devenv.lock`. The existing trusted
  JSON-only synchronizer validates the complete nixpkgs identity and all unrelated
  inputs. Both locks must already agree; admission waits for the scheduled trusted
  synchronizer if necessary. No candidate Nix expression is evaluated by the
  credentialed controller, and there is no generic lockfile exemption.

Before approving CI, the controller also inspects the immutable requested
workflow and local composite actions. Admitted jobs must use ephemeral hosted
runners, explicit read-only permissions, no secret references, no reusable job,
no attestation or cache-publishing action. Only exact known conditions excluding
both PR event types can justify skipping a privileged job. The ordinary PR CI
path disables reusable-output export and attestation. Automatic write-token hash
repair is removed; failures require a separately reviewed repair. CodeQL's PR
job is read-only; non-PR analysis retains its existing upload permission.

The allowlisted workflow ID/path, native associated PR, exact head/base, repository
IDs, initiating/rerun actors and run attempt are checked again before approval.
Missing, incomplete or ambiguous inventories, malformed input, moved heads and
API errors fail closed. Uncertain writes are not retried. Other author admission
and exact-current-head merge authority retain their previous restrictions.

The existing workflow completion wakeups and fifteen-minute reconciliation
schedule handle pending runs. No additional polling service is introduced.
These changes take effect only after this implementation is reviewed and merged;
a PR's own CI is not evidence that protected-main admission has been deployed.
