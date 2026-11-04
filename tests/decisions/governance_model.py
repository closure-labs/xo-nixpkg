"""Inactive migration reference model, not a signature verifier or live gate.

All proof-verification outcomes are injected test doubles. Production must use
pinned gh cryptographic verification and native API records at trust boundaries.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Acceptance:
    subject: str
    findings: frozenset
    policy: str
    issuer_workflow: str
    run: int
    attempt: int
    expires_at: int | None = None


def issue(*, subject, findings, policy, role, human, review_head, current_head,
          issuer_workflow, run, attempt, evidence_verified):
    # Proposed maintain/admin minimum is unresolved until the user confirms it.
    if (not human or role not in ('maintain', 'admin') or not evidence_verified
            or not subject or not findings or not policy or not issuer_workflow
            or review_head != current_head or not current_head
            or type(run) is not int or run < 1 or type(attempt) is not int or attempt != 1):
        raise ValueError('issuance-blocked')
    return Acceptance(subject, frozenset(findings), policy, issuer_workflow, run, attempt)


def consume(acceptance, *, current_role, subject, findings, policy,
            trusted_workflow, proof_verified, revoked, now):
    # current_role is intentionally irrelevant to an already sealed acceptance.
    # It must still be checked on each NEW issuance through issue().
    return bool(proof_verified and not revoked and acceptance.subject == subject
                and frozenset(findings) <= acceptance.findings
                and acceptance.policy == policy
                and acceptance.issuer_workflow == trusted_workflow
                and (acceptance.expires_at is None or now < acceptance.expires_at))


def readiness(*, native_reviews, stale_reviews, last_push_approval,
              environment_reviewers, environment_main_only,
              alternate_writers_verified, issuer_implemented, legacy_sealed,
              unresolved_decisions):
    missing = []
    for name, okay in (
        ('native-review-count', native_reviews >= 1),
        ('stale-review-dismissal', stale_reviews),
        ('last-push-approval', last_push_approval),
        ('environment-reviewer-pool', environment_reviewers),
        ('environment-main-only', environment_main_only),
        ('alternate-writers', alternate_writers_verified),
        ('trusted-issuer', issuer_implemented),
        ('legacy-migration', legacy_sealed),
        ('policy-decisions', not unresolved_decisions),
    ):
        if not okay:
            missing.append(name)
    # Even a complete model is not live approval or a settings-write command.
    return {'activation': 'inactive', 'authorityClaim': False,
            'status': 'blocked' if missing else 'ready-for-independent-review',
            'missing': missing}
