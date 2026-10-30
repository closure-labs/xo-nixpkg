<!-- SPDX-License-Identifier: Apache-2.0 -->
# Native Actions-pin fixture

Exact `.github/workflows/codeql.yml` Git blob bytes fetched read-only from
`closure-labs/xo-nixpkg` PR195 on 2026-10-30:

- Before/merge base: `c69059918d2947517648b8ed9cb6c74513b63a35`.
- After/head: `871c8f7298544d03d29a6e5d3a2d780fe422870c`.
- Both `github/codeql-action/{init,analyze}` pins change from
  `6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee` (`v4.39.0`) to
  `9b3254085494b55a0f7c4c2b3d2d52cc712ce370` (`v4.39.1`).
- Official upstream tag `v4.39.1` resolved via read-only `git ls-remote` to
  annotated tag `8498dc4c2b27cdd99baf0f87955b29ebbf30c78d`, peeled to that new SHA.

The test supplies synthetic PR/tree/run/review metadata around these real bytes;
it neither executes the workflow nor grants live approval.
