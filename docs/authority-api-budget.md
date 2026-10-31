# Authority API budget observations

Each publication authority gate emits only a bounded count of calls through its
GitHub authority API callback and a passed/blocked diagnostic state. The JSONL
artifact contains no endpoint, query, response, credential, finding, reviewer or
authority claim. It is not a count of every HTTP request: native observation,
attestation tooling and other external tools have separate transports.

The final complete current-main Git tree now supplies the policy's regular blob
identity directly. Existing Git-blob size/hash validation and job-local verified
immutable-byte reuse remain mandatory; the redundant Contents lookup is removed.
A final fresh main-ref comparison rejects movement during admission. Effective
rules, complete ledgers and current review/membership checks are still read.
There is no TTL cache or reuse of an authority conclusion, and no mutable HTTP
ETag cache. When the verified policy blob is already available (the normal configured CLI
path), the optimization removes one redundant policy Contents request per
successful authority boundary; it does not claim to solve total installation
quota exhaustion. Counts can establish which additional changes are worthwhile.

This draft is independently based on current protected main, not #212. It touches
common.py/observability.py rather than the retry adapter, and preserves retry and
release semantics. Hosted checks must run request-count, product authority,
revocation/race, immutable blob integrity, diagnostics and actionlint fixtures.
No local tests/builds/Nix evaluation ran on XPS.
