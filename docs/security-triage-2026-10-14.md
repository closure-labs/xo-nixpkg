<!-- SPDX-License-Identifier: Apache-2.0 -->
# npm critical finding applicability triage — 2026-10-14

This is a source and artifact review, not a blanket suppression list. The inspected output is `/nix/store/pmy7arxjj9zdwzxgbh31i4b53cax82cs-xen-orchestra-ce-6.9.1`, the XO artifact referenced by the Maestro findings. Different xo-nixpkg latest/stable/rolling outputs must repeat the guards against their actual installed trees. Raw findings, scanner/advisory identity bindings, explicit owners and the existing maximum 30-day decision expiry must remain intact.

## Decision matrix

| Finding | Installed version | Supported classification | Required conditions |
|---|---|---|---|
| tar GHSA-23hp-3jrh-7fpw | root 6.2.1 | **UNKNOWN; supporting server-profile evidence, incomplete closed call graph** | Complete resolved installed dependency graph and immutable entrypoint/plugin source identity prove root tar 6 is outside the server/plugin runtime graph. Runtime backups resolves tar 7.5.22, which is fixed. Current package/config evidence does not yet prove that closed-world condition. |
| handlebars GHSA-8r5x-fm3f-whwj | 4.7.9 | **Conditional not_affected for verified immutable XO report callers** | Every runtime compile/partial registration input is a UTF-8 string from immutable package templates. No untrusted object AST reaches compile/precompile. Effective plugin lookup roots must be immutable-only; missing launch/config proof yields UNKNOWN. |
| handlebars GHSA-p8wg-vrv2-v86f | 4.7.9 | **Conditional not_affected for verified immutable XO report callers** | Exact library and consumer source prove prototype-method access is not enabled; calls use default runtime options, with no global/prototype-access wrapper or custom runtime consumer. Effective plugin lookup roots must be immutable-only; missing launch/config proof yields UNKNOWN. |
| proxy-addr GHSA-jqcg-44mw-7w3h | 2.0.7 | **UNKNOWN for general xo-nixpkg/overridable Maestro configuration; conditional not_affected with enforced effective trust config** | Effective `http.useForwardedHeaders` is false or an exact reviewed safe list, e.g. `['loopback']`, and every config layer/update path is covered. No short mapped-IPv6/zero-leading-bit IPv6 trust subnet. |
| shell-quote GHSA-pqg4-j6r4-53mv | 1.8.4 | **UNKNOWN; supporting server-profile evidence, incomplete closed call graph** | Complete resolved installed dependency graph and immutable runtime roots exclude shell-quote and its consumers. Independently, known npm-run-all quote paths take string arrays, while outpipe/browserify call parse only. Do not generalize from these examples to unknown consumers. |

None of the flagged vulnerable root package versions is **fixed** merely because NixOS runs the server. The separate runtime tar 7.5.22 copy is fixed for this advisory; it is not the flagged tar 6.2.1 instance.

## Primary advisory verification

Exact GitHub global advisory records were fetched with `gh api advisories/GHSA-...`, and compared with repository-owner advisories. All five global records currently designate critical severity. The shell-quote repository advisory displays High/8.1 while the global record designates Critical; retain the scanner's original finding and record this discrepancy rather than silently downgrading it.

- **tar:** affected through 7.5.18, first fixed 7.5.19. The relevant operation is parsing/decompressing attacker-controlled archives without cumulative byte/entry limits. Creation alone does not establish this attack path. [Maintainer advisory](https://github.com/isaacs/node-tar/security/advisories/GHSA-23hp-3jrh-7fpw).
- **Handlebars AST confusion:** affected 4.0.0–4.7.9, first fixed 4.7.10. It requires an attacker-controlled object AST reaching compile/precompile; the maintainer explicitly excludes applications that only pass strings. [Maintainer advisory](https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-8r5x-fm3f-whwj).
- **Handlebars own-property bypass:** affected 3.0.0–4.7.9, first fixed 4.7.10. Rendering an attacker-controlled template with prototype-method access enabled can expose the Function constructor. The maintainer workaround prohibits enabling `allowProtoMethodsByDefault` for untrusted templates/data. [Maintainer advisory](https://github.com/handlebars-lang/handlebars.js/security/advisories/GHSA-p8wg-vrv2-v86f).
- **proxy-addr:** affected 1.1.0 through versions below 2.0.8; first fixed 2.0.8. Misconfigured mapped-IPv6 short prefixes or IPv6 subnets with zero leading bits can trust every IPv4 client and believe forged forwarded headers. Plain IPv4 CIDRs and properly mapped prefixes are recommended workarounds. [Maintainer advisory](https://github.com/jshttp/proxy-addr/security/advisories/GHSA-jqcg-44mw-7w3h).
- **shell-quote:** affected 1.8.4 through versions below 1.11.0; first fixed 1.11.0. A comment-token object followed by an attacker-controlled string containing a line terminator must enter the same quote call, then the output must reach a shell. A parse-only call is not this sink. [Maintainer advisory](https://github.com/ljharb/shell-quote/security/advisories/GHSA-pqg4-j6r4-53mv).

## Installed call-chain evidence

Paths below are relative to the immutable XO `libexec/xen-orchestra` tree unless noted otherwise.

### tar

- Root `node_modules/tar/package.json` declares 6.2.1. The installed supply graph identifies pacote 17.0.7, node-gyp 10.3.1 and cacache 18.0.4 as parents. The supply graph's synthetic XO root also connects all installed dependencies; that edge does not establish runtime use.
- `@xen-orchestra/backups/node_modules/tar/package.json` declares **7.5.22**. `_fileRestore.mjs:26` imports tar from the backups workspace, so Node resolves the nested fixed copy. `_fileRestore.mjs:316` calls `tar.c({cwd:path,gzip:true,jobs:1},...)`, archive creation. Do not confuse npm tar with xo-server's separate `tar-stream` operations.
- Positive dependency traversal from xo-server and every installed xo-server-* plugin reaches tar 7.5.22, but does not reach root tar 6.2.1, node-gyp, pacote or cacache. This is stronger than process sampling; it still needs a validated closed runtime root set and correct installed resolution graph.
- Existing extraction sinks in `node_modules/node-gyp/lib/install.js` and `node_modules/pacote/lib/fetcher.js` remain real for tool invocation. An arbitrary package consumer or mutable runtime plugin could use them. They are not erased by a server-specific classification.

### Handlebars

- Backup reports `packages/xo-server-backup-reports/templates/index.js:66` compiles `readFileSync(...,'utf-8').replace(...)`; partial registration at line 56 uses UTF-8 reads too. Directories are derived from the immutable module's `__dirname`.
- Perf alerts `packages/xo-server-perf-alert/dist/templates/index.js:78` uses the same string file-read compile pattern; partial registration at line 69 also reads UTF-8 strings.
- Usage reports `packages/xo-server-usage-report/src/index.js:47–59` reads `../report.html.tpl` as UTF-8, minifies the string, then compiles it. Compiled dist code preserves that flow. The data passed at render time is separate from the template input.
- No `allowProtoMethodsByDefault`/`allowProtoPropertiesByDefault` override was found in these runtime consumers. This negative search alone is insufficient; exact source identities and reviewed actual compile/render expressions must be bound.
- Additional installed consumers include @tsoa/cli and @vue/compiler-sfc build tooling. @tsoa/cli's generator compiles customizable template values; those contexts are outside a server-only not_affected claim. Unknown new/plugin consumers must fail eligibility.

### proxy-addr

- `packages/xo-server/dist/index.mjs:865` compiles watched `http.useForwardedHeaders` values; line 869 gives the resulting trust function to Express. Lines 657 and 718 also use it for API upgrade and console-proxy client identity.
- Shipped `packages/xo-server/config.toml:146` uses `['loopback']`. In the exact installed library, this expands to safe loopback subnets. It is not the vulnerable short mapped-IPv6 configuration.
- Maestro `modules/_nixos/xo/service.nix:33` renders HTTP listener/TLS fragments, but does not currently bind `useForwardedHeaders`. Mutable operator/config layers are therefore not covered by the current source-only evidence. Private management CIDRs are not an applicability argument for this bug.
- The defensible gate must inspect/enforce effective trust settings and configuration precedence or select a package patched/upgraded to 2.0.8. A generic xo-nixpkg package cannot promise every consuming NixOS configuration uses the safe value.

### shell-quote

- Installed parents are outpipe 1.1.1, browserify 16.5.2, npm-run-all 4.1.5 and npm-run-all2 7.0.2. The server/plugin dependency closure does not reach any of these or shell-quote itself.
- outpipe `index.js:1` and browserify `bin/args.js:4` import parse, not quote. Their own arbitrary command execution behavior is distinct from this quote-specific advisory.
- npm-run-all `lib/index.js:52,55,60,68,72` and npm-run-all2 corresponding placeholder helpers quote string argument arrays or individual string slices. The exposed programmatic API and future consumers still require review; CLI-string call sites alone cannot justify a universal package exemption.
- Vite's distribution embeds shell-quote 1.8.4; its inspected editor-selection call uses parse. It is build/development tooling rather than a declared XO server dependency, but the installed tree should retain that evidence too.

## Reproducible dependency traversal

The graph check used the installed CycloneDX supply inventory's component identities and resolved dependencies, not guessed names from output suffixes. Roots included xo-server and all 21 installed xo-server-* plugins, so the proof did not rely on current plugins being disabled.

```text
$ python3 - <<'PY'
import json
inventory = json.load(open('xen-orchestra-supply.cdx.json'))
components = {c['bom-ref']: c for c in inventory['components']}
edges = {d['ref']: d.get('dependsOn', []) for d in inventory.get('dependencies', [])}
pending = [ref for ref, c in components.items() if c['name'] == 'xo-server' or c['name'].startswith('xo-server-')]
seen = set()
while pending:
    ref = pending.pop()
    if ref not in seen:
        seen.add(ref)
        pending.extend(edges.get(ref, []))
for name, version in [('tar','7.5.22'),('tar','6.2.1'),('handlebars','4.7.9'),('proxy-addr','2.0.7'),('shell-quote','1.8.4'),('node-gyp','10.3.1'),('pacote','17.0.7'),('cacache','18.0.4'),('outpipe','1.1.1'),('npm-run-all','4.1.5'),('npm-run-all2','7.0.2'),('browserify','16.5.2')]:
    for ref, c in components.items():
        if (c['name'], c.get('version')) == (name, version):
            print(name, version, 'server_declared_runtime_reachable', ref in seen)
print('reachable', len(seen))
PY
tar 7.5.22 server_declared_runtime_reachable True
tar 6.2.1 server_declared_runtime_reachable False
handlebars 4.7.9 server_declared_runtime_reachable True
proxy-addr 2.0.7 server_declared_runtime_reachable True
shell-quote 1.8.4 server_declared_runtime_reachable False
node-gyp 10.3.1 server_declared_runtime_reachable False
pacote 17.0.7 server_declared_runtime_reachable False
cacache 18.0.4 server_declared_runtime_reachable False
outpipe 1.1.1 server_declared_runtime_reachable False
npm-run-all 4.1.5 server_declared_runtime_reachable False
npm-run-all2 7.0.2 server_declared_runtime_reachable False
browserify 16.5.2 server_declared_runtime_reachable False
reachable 1182
```

## Minimum machine-checkable applicability contract

1. Bind advisory ID/digest, exact npm identity/version/manifest path, immutable XO output and source revision, full package source/derivation identity, and runtime launch profile. The current supply inventory hashes **package.json only** (`nix/supply-inventory.py:70`); that does not establish unchanged vulnerable/consumer JavaScript. Add explicit code-file hashes or a verified full artifact-tree identity.
2. For runtime-only exclusions, validate the closed entrypoint/plugin root list, complete installed dependency resolution, and absence of external runtime modules/custom plugins. A new reachable dependency, unreviewed dynamic import, missing module, resolution error or changed source becomes UNKNOWN and blocks eligibility.
3. For Handlebars, positively verify exact reviewed compile, partial registration and render call sites plus immutable template roots. Require string-only compile inputs for the AST advisory; require default/explicitly restrictive prototype permissions for the own-property advisory. Changes in library, consumers or template handling invalidate both decisions.
4. For proxy-addr, bind effective `http.useForwardedHeaders` and all config layers to the runtime context. Enforce reviewed safe values or use an actual fixed dependency. A caller-provided exposure boolean or unattested config assertion is not evidence.
5. Evaluate separately for Maestro's actual NixOS profile and each xo-nixpkg package channel. The shared package-level profile can prove immutable server code; it cannot infer consuming-host firewall, proxy, user config or custom plugins.
6. Preserve every raw scanner match in reports. Eligibility adds evidence-backed classification; it must not remove the dependency from the inventory. Unknown, source drift, expired decisions, malformed evidence or missing guards must remain visible and fail closed when enforcement is active.

## Artifact evidence

The review captured exact library, consumer and launcher hashes locally. They are research evidence, not approved applicability rules. The package rule set remains empty; all five matches stay visible and unresolved until complete guards and existing deployment acceptance gates pass.

## Additional decisive runtime constraints and probe

`packages/xo-server/dist/index.mjs:443` dynamically discovers plugins from effective `plugins.lookupPaths`. Shipped `config.toml:254` includes `['./node_modules','../','/usr/local/lib/node_modules']`. Therefore the graph traversal is supporting evidence, not a complete call-graph exclusion. No production decision should be generated for tar6 or shell-quote from that graph alone. Both Handlebars candidates also need an effective immutable-only plugin-root and exact launch profile guard; the package alone cannot certify that operator config permits no external plugin. A missing guard means UNKNOWN, even when every inspected built-in plugin is safe.

A harmless test with the exact installed XO Node22.23.3 runtime and proxy-addr2.0.7 inside the native shell established the configuration distinction:

```text
$ devenv shell -- /nix/store/aavcwg0x51gplaalfx5qlgq24l4vjxv3-nodejs-22.23.3/bin/node - <<'JS'
const root = '/nix/store/pmy7arxjj9zdwzxgbh31i4b53cax82cs-xen-orchestra-ce-6.9.1/libexec/xen-orchestra';
const proxy = require(root + '/node_modules/proxy-addr');
for (const subnet of [['loopback'], ['10.0.0.0/8'], ['::ffff:10.0.0.0/8']]) {
  const trust = proxy.compile(subnet);
  console.log(JSON.stringify({subnet, trustsExternal:trust('203.0.113.17',0), trustsLoopback:trust('127.0.0.1',0)}));
}
JS
{"subnet":["loopback"],"trustsExternal":false,"trustsLoopback":true}
{"subnet":["10.0.0.0/8"],"trustsExternal":false,"trustsLoopback":false}
{"subnet":["::ffff:10.0.0.0/8"],"trustsExternal":true,"trustsLoopback":true}
```

This test did not send network requests or execute injected shell/JavaScript code. It proves that the version remains vulnerable in the bad configuration and that reviewed safe subnet lists are a valid prospective guard. It does not prove the configuration of a deployed appliance.
