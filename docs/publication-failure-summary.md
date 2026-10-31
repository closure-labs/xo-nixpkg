# Partial publication diagnostics

On a handled exception the publication controller atomically replaces any stale
success summary with `status: incomplete`, `authorityClaim: false`, a fixed stage,
locally confirmed completed journal checkpoints and invocation-attempt counters.
Exception text, command arguments, findings, API bodies and credentials are not
serialized. An attempted operation is not a completion claim; the durable journal
and fresh destination verification remain the recovery authority.

The existing always-upload step retains this file without adding permissions or
changing publication gates. Abrupt runner termination can still prevent writing
an artifact; absence remains unknown, never success. A diagnostic-write failure
does not replace the original publication error. Success summaries retain their
existing schema. Hosted publication-result, journal-readback, partial cache and
redaction fixtures must pass; no local tests/builds/Nix evaluation ran on XPS.
