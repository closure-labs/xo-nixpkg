import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

// Exercise the actual pinned sources, including both the older restore methods
// and upstream's symlink-safe paths and partition cache. No host mounts are run.
const sources = process.argv.slice(2)
assert.equal(sources.length, 3, 'pass the latest, stable, and rolling source directories')
const patch = await readFile(new URL('../nix/patches/xo-isolated-file-restore.patch', import.meta.url))
const paths = [
  '@xen-orchestra/backups/_fileRestore.mjs',
  'packages/xo-server/src/xo-mixins/file-restore-ng.mjs',
]
for (const source of sources) {
  const directory = await mkdtemp(join(tmpdir(), 'xo-restore-patch-'))
  try {
    const originals = await Promise.all(paths.map(path => readFile(join(source, path), 'utf8')))
    for (const [index, path] of paths.entries()) {
      await mkdir(dirname(join(directory, path)), { recursive: true })
      await writeFile(join(directory, path), originals[index])
    }
    // Reject fuzzy application, especially around upstream security changes.
    execFileSync('patch', ['--batch', '--fuzz=0', '-p1', '-d', directory], { input: patch, stdio: ['pipe', 'inherit', 'inherit'] })
    // The xo-server mixin uses Babel decorators, so only the plain ESM module
    // can be checked directly by Node.
    execFileSync(process.execPath, ['--check', join(directory, paths[0])])
    const patched = await readFile(join(directory, paths[0]), 'utf8')
    const match = patched.match(/export const fileRestoreMethods = (\{[\s\S]*?\n\})\n/)
    assert.ok(match, 'find the actual patched restore methods')
    // Bind only the dependencies needed by the isolated branches. Any host
    // mount/probe reached by accident will fail instead of touching the host.
    const methodsFor = helper => new Function('isolatedFileRestore', 'Disposable', `return (${match[1]})`)(
      helper, { use: async (disk, callback) => callback(disk) }
    )
    const calls = []
    const methods = methodsFor({
      listPartitions: (...args) => { calls.push(['partitions', ...args]); return ['isolated partition'] },
      listPartitionFiles: (...args) => { calls.push(['files', ...args]); return { 'guest.txt': {} } },
    })
    const adapter = {
      getDisk: id => `disk:${id}`,
      get _partitionsCache() { throw new Error('isolated restores must bypass the host partition cache') },
    }
    assert.deepEqual(await methods.listPartitions.call(adapter, 'backup'), ['isolated partition'])
    assert.deepEqual(await methods.listPartitionFiles.call(adapter, 'backup', 'partition', '/etc'), { 'guest.txt': {} })
    assert.deepEqual(calls, [
      ['partitions', 'disk:backup'],
      ['files', 'disk:backup', 'partition', '/etc'],
    ])
    await assert.rejects(methods.getPartition.call(adapter, 'backup', 'partition').next(), /host partition mounting is disabled/)

    if (originals[0].includes('const cache = this._partitionsCache')) {
      const cached = Promise.resolve(['cached host partition'])
      assert.equal(methodsFor(undefined).listPartitions.call({ _partitionsCache: new Map([['backup', cached]]) }, 'backup'), cached)
    }
    // Every upstream line must survive in order, including symlink validation
    // and cache cleanup. The patch adds dispatch/guards, not replacement logic.
    for (const [index, path] of paths.entries()) {
      const lines = (await readFile(join(directory, path), 'utf8')).split('\n')
      let position = 0
      for (const line of originals[index].split('\n')) {
        const next = lines.indexOf(line, position)
        assert.notEqual(next, -1, `upstream line was removed or changed: ${line}`)
        position = next + 1
      }
    }
    execFileSync('patch', ['--batch', '--fuzz=0', '-R', '-p1', '-d', directory], { input: patch, stdio: ['pipe', 'inherit', 'inherit'] })
    for (const [index, path] of paths.entries()) {
      assert.equal(await readFile(join(directory, path), 'utf8'), originals[index])
    }
    console.log(`isolated file restore patch and dispatch passed: ${source}`)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}
