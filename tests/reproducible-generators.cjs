// SPDX-License-Identifier: Apache-2.0
// Exercise pinned public-source fixtures, never retained artifact programs.
const fs = require('node:fs')
const path = require('node:path')
const os = require('node:os')
const vm = require('node:vm')
const crypto = require('node:crypto')
const { EventEmitter } = require('node:events')
const { spawnSync } = require('node:child_process')
const root = path.resolve(__dirname, '..')
class FixtureFailure extends Error {}
const check = (value, code) => { if (!value) throw new FixtureFailure(code) }
const sha = value => crypto.createHash('sha256').update(value).digest('hex')
function bounded(promise) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new FixtureFailure('fixture-timeout')), 2000)
    promise.then(value => { clearTimeout(timer); resolve(value) }, error => { clearTimeout(timer); reject(error) })
  })
}
function patchedSource(temp, fixture, moduleFile, patchFile, digest) {
  const original = fs.readFileSync(path.join(__dirname, 'fixtures/reproducibility', fixture), 'utf8')
  check(sha(original) === digest, 'fixture-source-identity')
  const directory = path.join(temp, fixture)
  const target = path.join(directory, moduleFile)
  fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, original)
  const result = spawnSync('patch', ['--batch', '--fuzz=0', '-p1', '-d', directory, '-i', path.join(root, 'nix/patches', patchFile)], { stdio: 'ignore', timeout: 2000 })
  check(result.status === 0, 'actual-production-patch-failed')
  return { original, patched: fs.readFileSync(target, 'utf8') }
}
function asyncFn(generator) {
  return function (...args) {
    const iterator = generator.apply(this, args)
    return new Promise((resolve, reject) => {
      function advance(method, value) {
        let step
        try { step = iterator[method](value) } catch (error) { reject(error); return }
        if (step.done) resolve(step.value)
        else Promise.resolve(step.value).then(value => advance('next', value), error => advance('throw', error))
      }
      advance('next')
    })
  }
}
function runIndex(code, entries, delays, lazy = false) {
  return bounded(new Promise((resolve, reject) => {
    const fakeFs = {
      readdir(directory, callback) { queueMicrotask(() => callback(null, entries)) },
      stat(file, callback) { setTimeout(() => callback(null, { isDirectory: () => false, isFile: () => true }), delays[path.basename(file)] || 1) },
      writeFile(file, text, callback) { queueMicrotask(() => { callback(null); resolve(text) }) }
    }
    const dependencies = {
      'promise-toolbox': { asyncFn, promisify: fn => (...args) => new Promise((resolve, reject) => fn(...args, (error, value) => error ? reject(error) : resolve(value))) },
      'lodash/camelCase': value => value,
      path, fs: fakeFs,
      getopts: () => ({ _: ['/fixture/modules'], 'index-file': 'index.mjs', 'import-ext': '', 'cjs-lazy': lazy })
    }
    try {
      vm.runInNewContext(code, { require: name => { check(name in dependencies, 'undeclared-index-dependency'); return dependencies[name] },
        process: { argv: ['node', 'index.js', '/fixture/modules'], stdout: { write() {} }, stderr: { write() {} } }, Promise }, { timeout: 500 })
    } catch (error) { reject(error) }
  }))
}
async function runDocs(code, files, delays, time, identity) {
  const written = {}; let globalData
  class Worker extends EventEmitter {
    postMessage(file) {
      if (file === null) { queueMicrotask(() => this.emit('exit', 0)); return }
      setTimeout(() => {
        this.emit('message', [true, { title: file.url, type: 0, content: 'fixture body', url: file.url }])
        this.emit('message', [null, 1])
      }, delays[file.url] || 1)
    }
  }
  function lunr(callback) {
    const documents = []
    const builder = { ref() {}, field() {}, add(value) { documents.push(value) }, build() { return { documents } } }
    callback.call(builder, builder)
    return builder.build()
  }
  const dependencies = {
    fs: { writeFileSync(file, text) { written[path.basename(file)] = JSON.parse(text) } },
    os: { cpus: () => [{}, {}] }, path, lunr,
    worker_threads: { Worker }, gauge: class { show() {} pulse() {} hide() {} },
    './utils': { getFilePaths: () => [files.map(file => ({ ...file })), { excludedCount: 0 }] }
  }
  const module = { exports: {} }
  vm.runInNewContext(code, { module, require: name => { check(name in dependencies, 'undeclared-docs-dependency'); return dependencies[name] },
    __dirname: '/fixture/lunr', process: { env: { XO_DOCS_BUILD_ID: identity } }, Date: { now: () => time },
    console: { log() {}, time() {}, timeEnd() {} }, Promise }, { timeout: 500 })
  const plugin = module.exports({}, {})
  await plugin.contentLoaded({ actions: { setGlobalData(value) { globalData = value } } })
  await bounded(plugin.postBuild({ routesPaths: [], outDir: '/output', baseUrl: '/', plugins: [] }))
  return { written, globalData }
}
async function main() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'generator-repro-'))
  try {
    const index = patchedSource(temp, 'index-modules-0.4.3.js', 'index.js', 'index-modules-deterministic.patch', '0012f612dfefee77740b8368f69a7656cd2980e4970c914fdcd64da21969e81e')
    const entries = ['alpha.mjs', 'beta.mjs', '.hidden.mjs', '_private.mjs', 'notes.txt']
    const slowA = { 'alpha.mjs': 12, 'beta.mjs': 1 }; const slowB = { 'alpha.mjs': 1, 'beta.mjs': 12 }
    const beforeA = await runIndex(index.original, entries, slowA)
    const beforeB = await runIndex(index.original, entries, slowB)
    check(beforeA !== beforeB, 'fixture-must-reproduce-completion-order-race')
    for (const lazy of [false, true]) {
      const afterA = await runIndex(index.patched, entries, slowA, lazy)
      const afterB = await runIndex(index.patched, [...entries].reverse(), slowB, lazy)
      check(afterA === afterB, 'module-order-must-ignore-enumeration-and-completion-order')
      check(!afterA.includes('hidden') && !afterA.includes('private') && !afterA.includes('notes'), 'upstream-module-filter-preserved')
    }
    const docs = patchedSource(temp, 'docusaurus-lunr-search-3.6.0.js', 'src/index.js', 'docusaurus-lunr-search-reproducible.patch', '792c072bf2923791252b10c3dfc9dd6eee5cbd85d80429143fcdd433ef7bad1c')
    const files = [{ path: '/output/b.html', url: '/b' }, { path: '/output/a.html', url: '/a' }]
    const identity = 'a'.repeat(32)
    const beforeDocsA = await runDocs(docs.original, files, { '/a': 12, '/b': 1 }, 1700000000000, identity)
    const beforeDocsB = await runDocs(docs.original, [...files].reverse(), { '/a': 1, '/b': 12 }, 1800000000000, identity)
    check(JSON.stringify(beforeDocsA.globalData) !== JSON.stringify(beforeDocsB.globalData), 'fixture-must-reproduce-wall-clock-filenames')
    check(JSON.stringify(beforeDocsA.written['search-doc.json']) !== JSON.stringify(beforeDocsB.written['search-doc.json']), 'fixture-must-reproduce-worker-order-race')
    const afterDocsA = await runDocs(docs.patched, files, { '/a': 12, '/b': 1 }, 1700000000000, identity)
    const afterDocsB = await runDocs(docs.patched, [...files].reverse(), { '/a': 1, '/b': 12 }, 1800000000000, identity)
    check(JSON.stringify(afterDocsA) === JSON.stringify(afterDocsB), 'search-bytes-and-ids-must-ignore-clock-route-and-worker-order')
    const newIdentity = await runDocs(docs.patched, files, {}, 1800000000000, 'b'.repeat(32))
    check(JSON.stringify(afterDocsA.globalData) !== JSON.stringify(newIdentity.globalData), 'cache-buster-must-change-with-output-identity')
    let rejected = false
    try { await runDocs(docs.patched, files, {}, 1700000000000, 'invalid') } catch (_) { rejected = true }
    check(rejected, 'invalid-docs-identity-must-fail')
    const installed = path.join(temp, 'installed'); const outside = path.join(temp, 'outside')
    for (const directory of [installed, outside]) {
      fs.mkdirSync(path.join(directory, 'packages/pkg/.turbo'), { recursive: true })
      fs.writeFileSync(path.join(directory, 'packages/pkg/.turbo/turbo-build.log'), 'fixture timing')
      fs.writeFileSync(path.join(directory, 'runtime.js'), 'runtime')
    }
    fs.writeFileSync(path.join(installed, 'packages/pkg/.turbo/preserve.json'), '{}')
    fs.symlinkSync(outside, path.join(installed, 'linked'), 'dir')
    const cleanup = spawnSync('bash', [path.join(root, 'nix/cleanup-turbo-logs.sh'), installed], { stdio: 'ignore', timeout: 2000 })
    check(cleanup.status === 0 && !fs.existsSync(path.join(installed, 'packages/pkg/.turbo/turbo-build.log')), 'build-log-removed')
    check(fs.readFileSync(path.join(installed, 'runtime.js'), 'utf8') === 'runtime' && fs.existsSync(path.join(installed, 'packages/pkg/.turbo/preserve.json')), 'runtime-and-other-metadata-preserved')
    check(fs.existsSync(path.join(outside, 'packages/pkg/.turbo/turbo-build.log')), 'cleanup-must-not-follow-directory-symlinks')
    const reject = spawnSync('bash', [path.join(root, 'nix/cleanup-turbo-logs.sh'), path.join(installed, 'linked')], { stdio: 'ignore', timeout: 2000 })
    check(reject.status !== 0, 'symlink-root-rejected')
    console.log('Generator reproducibility fixtures passed: ordering, clock, cache identity and runtime preservation')
  } finally { fs.rmSync(temp, { recursive: true, force: true }) }
}
main().catch(error => { console.error(error instanceof FixtureFailure ? error.message : 'Unexpected generator fixture failure'); process.exitCode = 1 })
