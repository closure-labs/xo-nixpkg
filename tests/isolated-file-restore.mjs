import assert from 'node:assert/strict'
import { mkdtemp, writeFile, chmod, rm, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout } from 'node:timers/promises'
import { createIsolatedFileRestore } from '../nix/isolated-file-restore.mjs'

assert.equal(createIsolatedFileRestore(undefined), undefined)
assert.throws(() => createIsolatedFileRestore('relative'), /absolute/)
const directory = await mkdtemp(join(tmpdir(), 'xo-restore-hook-'))
try {
  const helper = join(directory, 'helper.mjs')
  await writeFile(helper, `#!${process.execPath}
import { writeFileSync } from 'node:fs'
let input = ''
for await (const chunk of process.stdin) input += chunk
const request = JSON.parse(input)
if (request.version !== 1) process.exit(2)
if (request.disk === 'failure') { console.error('fixture error'); process.exit(3) }
if (request.disk === 'oversized') { process.stdout.write('x'.repeat(2 * 1024 * 1024)) }
if (request.operation === 'partitions') process.stdout.write(JSON.stringify([{ id: '/dev/sda1', size: 42 }]))
if (request.operation === 'files') process.stdout.write(JSON.stringify({ 'fixture.txt': {} }))
if (request.operation === 'archive') {
  if (request.disk.startsWith('/')) {
    writeFileSync(request.disk, String(process.pid))
    setInterval(() => process.stdout.write('archive-data'), 20)
  } else process.stdout.write('archive-data')
}
`)
  await chmod(helper, 0o755)
  const backend = createIsolatedFileRestore(helper)
  assert.deepEqual(await backend.listPartitions('fixture'), [{ id: '/dev/sda1', size: 42 }])
  assert.deepEqual(await backend.listPartitionFiles('fixture', '/dev/sda1', '/'), { 'fixture.txt': {} })
  await assert.rejects(backend.listPartitions('failure'), /fixture error/)
  await assert.rejects(backend.listPartitions('oversized'), /response exceeds/)
  await assert.rejects(createIsolatedFileRestore(join(directory, 'absent')).listPartitions('fixture'), /ENOENT/)
  const chunks = []
  for await (const chunk of backend.fetchPartitionFiles('fixture', '/dev/sda1', ['/'], 'zip')) chunks.push(chunk)
  assert.equal(Buffer.concat(chunks).toString(), 'archive-data')
  const pidFile = join(directory, 'pid')
  const stream = backend.fetchPartitionFiles(pidFile, '/dev/sda1', ['/'], 'tgz')
  await new Promise((resolve, reject) => { stream.once('data', resolve); stream.once('error', reject) })
  const pid = Number(await readFile(pidFile, 'utf8'))
  stream.destroy()
  await stream.restoreFinished
  let stopped = false
  for (let attempt = 0; attempt < 100; attempt++) {
    await setTimeout(20)
    try { process.kill(pid, 0) } catch (error) { if (error.code === 'ESRCH') { stopped = true; break } throw error }
  }
  assert.equal(stopped, true, 'client disconnect must stop the helper')
  console.log('isolated file restore protocol and cancellation fixtures passed')
} finally {
  await rm(directory, { recursive: true, force: true })
}
