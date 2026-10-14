<!-- SPDX-License-Identifier: Apache-2.0 -->
# CI pilot measurements, 2026-10-14

These pilots extend trusted prewarming and run selected cheap contracts before
expensive targets. They preserve patched Node/OpenSSL, all selected VM, supply
and linkage checks, and the report-mode critical applicability policy merged in
main `f375273ee680121d9fc428569b8238b664b4ca77`.

## Local measurements

| Case | Measured elapsed | Observed result |
| --- | ---: | --- |
| Full local validation | 61 s summed per-target time | 18 successes: 8 preflight and 10 runtime targets |
| Deliberately invalid queue checkout | 49.941 s wall time | Policy failed in 6 s; no runtime stage started |
| Empty isolated-store public runtime substitution | 6.749 s wall time | 60 paths, 77.8 MiB download / 257.0 MiB unpacked |
| Repeated substitution into that populated store | 0.035 s wall time | Exact output already present |

The complete validation used the pinned native development/packaged tools on a
workstation with previously realized runtime outputs. The integer per-target
receipt includes command startup and realization; the summed 61 seconds excludes
initial whole-flake evaluation. It demonstrates retained coverage, not a cold
build speedup. A later exact-head validation also accompanies the pilot PR.

The failed case used a separate disposable JJ clone and changed only privileged
queue checkout from the default branch to `untrusted-candidate`. The real policy
derivation rejected it; all eight cheap targets were collected before aborting.
No runtime manifest was produced. The deliberate invalid commit is never pushed.

The substitution benchmark created a new local Nix store under a temporary root
and ran `nix-store --store 'local?root=…' --realise OUTPUT`, with only the signed
XO and NixOS public caches as substituters. Logs identify both remote caches as
the source of downloads. The exact runtime output was:

```text
/nix/store/aavcwg0x51gplaalfx5qlgq24l4vjxv3-nodejs-22.23.3
```

The public-key requirement remained enabled. This is a cold destination cache
import, followed by a warm repeat, not a cold Node compilation or a hosted-run
benchmark. The workstation store and existing cache objects were not deleted.
An earlier local-copy experiment used fallback copying and is excluded from the
public-cache measurements above.

## Validation and limitations

ShellCheck, shell syntax, actionlint, zizmor, classifier, plan-runner, CI-runtime,
trusted-prewarm and repository policy fixtures passed through the pinned native
toolchain. Fixtures reject PR refs/events, unprotected branches, changed scripts,
undeclared channels and unexpected output roots before cache publication. They
also exercise full selected-target coverage and preflight failure stopping the
runtime stage. The protected write workflows cannot be exercised from a pilot
PR without merging them or granting that branch write privileges.

No local XO write credential was available. Actual authenticated writes to the
`xen-orchestra-ce` destination are therefore unmeasured; successful/failed pushes
are tested with fixtures. The workflow keeps that existing protected-main cache
destination. Any optional workstation seed to the operator's Maestro cache is
separate and does not establish XO-cache upload performance.

Historically, the identical patched Node derivation compiled for 82m16s in
[PR validation](https://github.com/closure-labs/xo-nixpkg/actions/runs/38484003540/job/115593191042),
80m16s in [merge-group validation](https://github.com/closure-labs/xo-nixpkg/actions/runs/38496093522/job/115632106882),
and 66m56s in [main publication](https://github.com/closure-labs/xo-nixpkg/actions/runs/38506952665/job/115666590600).
Those intervals motivate prewarming; this pilot does not claim all 229 minutes
will be saved. A subsequent protected-main updater/manual prewarm and fresh
hosted PR/merge/publication cycle must measure actual upload, cache hits, retained
checks and total elapsed time before making hosted performance claims.
