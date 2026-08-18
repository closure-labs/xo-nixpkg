<!-- SPDX-License-Identifier: Apache-2.0 -->
# Documentation

Start with the commands in the [README](../README.md), then use these focused
guides when you need more detail:

- [Configuration](configuration.md): flake inputs, NixOS package selection,
  cache behavior, FUSE boundaries, and reusable CI plans
- [Development](development.md): toolchain setup, upstream source updates,
  release versioning, and core synchronization
- [Testing](testing.md): package, linkage, service, fixture, and CI validation
- [Nixpkgs submission](nixpkgs-submission.md): preparing either package for
  upstream review

Project releases use the repository `VERSION`. Package versions remain visible
on their package attributes and follow their respective upstream sources.
