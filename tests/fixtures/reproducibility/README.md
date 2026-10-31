# Generator regression fixtures

These source files are test fixtures, never fetched retained-output programs.

- index-modules 0.4.3, ISC, copyright Julien Fontanet. Source commit b60bd9400cb5f13c4c32678643d163ab8526a405, SHA256 0012f612dfefee77740b8368f69a7656cd2980e4970c914fdcd64da21969e81e. https://github.com/JsCommunity/index-modules
- docusaurus-lunr-search 3.6.0, MIT, copyright Praveen N and contributors. The package source is verified against the locked Yarn SHA512 integrity; src/index.js SHA256 792c072bf2923791252b10c3dfc9dd6eee5cbd85d80429143fcdd433ef7bad1c. https://github.com/praveenn77/docusaurus-lunr-search

The repository changes are applied using the actual production patch files. Dependencies and filesystem/worker timing are deterministic test doubles; no third-party dependency installation or retained-artifact execution occurs.
