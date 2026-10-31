# GitHub read retry contract

`ci/decisions/github_retry.py` is a credential-free policy for fresh GET requests.
The XO authority adapter uses at most three attempts within 45 monotonic seconds,
also bounded by the enclosing operation deadline. Each transport gets at most
30 seconds and only the budget remaining. No authority conclusion is cached.
Mutations are not retried by this helper.

Retry-After supports nonnegative integer seconds and aware HTTP dates. Valid
primary reset timestamps and Retry-After are minimum not-before times; neither
is shortened to fit the budget. Positive jitter is bounded to 0.05–0.25 seconds.
A future reset outside the budget, missing/stale primary reset, malformed or
ambiguous Retry-After, exhausted attempts or deadline fails closed without sleep
past the allowed budget. Secondary throttles without a server delay require at
least 60 seconds; the default45s adapter therefore defers them to scheduling.
A permitted request must reread current authority after waiting.

403 retries require explicit primary/secondary throttle evidence or valid server
Retry-After. Permission denials and unrelated 4xx remain terminal. 429 is a
throttle; transient transport/timeouts,408,500,502,503,504 retain bounded retries.
Malformed response/header framing, signals, oversized output and invalid JSON
remain terminal in the existing adapter. HTTP status and validated rate metadata
are safe diagnostics; arbitrary response bodies, headers and auth never appear.
The helper owns no token, credential fallback, quota expansion or permission.

References: [GitHub rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
and [retry guidance](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#handle-rate-limit-errors-appropriately).

Porting: copy the pure helper and deterministic `test_github_retry.py` contract
only after XO hosted validation, then adapt each repository's existing bounded
GET transport/header parser. Preserve live source/head/review checks and existing
safe diagnostics. Never apply it as a blind mutation retry or cache for authority.
HTTP-date conversion uses the initial wall/monotonic anchor; the injected sleeper
must honor requested delays. Fixtures use a fake clock, not real waiting/network.

No local tests/builds/Nix evaluation ran on XPS. Hosted CI must validate the new
contract and existing authority, operation-deadline, redaction, decision and
publication-boundary fixtures before cross-repository adoption.
