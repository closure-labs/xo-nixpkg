// Protocol v1: trusted absolute helper, bounded JSON input, JSON or archive output.
// The helper owns guest-kernel isolation. There is no privileged fallback once set.
import { spawn } from 'node:child_process'
import { isAbsolute } from 'node:path'
import { PassThrough } from 'node:stream'

export function createIsolatedFileRestore(helper) {
  if (helper === undefined || helper === '') return undefined
  if (!isAbsolute(helper)) throw new Error('XO_FILE_RESTORE_HELPER must be absolute')

  const invoke = request => {
    const child = spawn(helper, [], { stdio: ['pipe', 'pipe', 'pipe'] })
    const stream = new PassThrough()
    let errors = ''
    let closed = false
    let kill
    const stop = () => {
      if (closed || kill !== undefined) return
      child.kill('SIGTERM')
      kill = setTimeout(() => { if (!closed) child.kill('SIGKILL') }, 10000)
      kill.unref()
    }
    const timeout = setTimeout(stop, 15 * 60 * 1000)
    timeout.unref()
    // A disconnected client closes its stream before the guest appliance has
    // exited. Keep the disposable raw VHD view until the helper is reaped.
    stream.restoreFinished = new Promise(resolve => child.once('close', resolve))
    child.stderr.on('data', chunk => { errors = (errors + chunk.toString()).slice(-8192) })
    child.on('error', error => stream.destroy(error))
    child.stdin.on('error', error => stream.destroy(error))
    child.stdout.on('error', error => stream.destroy(error))
    child.stdout.pipe(stream, { end: false })
    child.once('close', (code, signal) => {
      closed = true
      clearTimeout(timeout)
      clearTimeout(kill)
      if (code === 0) stream.end()
      else stream.destroy(new Error(`isolated file restore failed (${signal ?? code}): ${errors}`))
    })
    stream.once('close', stop)
    const input = JSON.stringify({ version: 1, ...request })
    if (Buffer.byteLength(input) > 65536) stream.destroy(new Error('restore request exceeds limit'))
    else child.stdin.end(input)
    return stream
  }

  const json = async request => {
    const stream = invoke(request)
    let output = ''
    for await (const chunk of stream) {
      output += chunk.toString()
      if (Buffer.byteLength(output) > 1024 * 1024) {
        stream.destroy()
        throw new Error('restore response exceeds limit')
      }
    }
    return JSON.parse(output)
  }

  return {
    listPartitions: disk => json({ operation: 'partitions', disk }),
    listPartitionFiles: (disk, partition, path) => json({ operation: 'files', disk, partition, path }),
    fetchPartitionFiles: (disk, partition, paths, format) => invoke({ operation: 'archive', disk, partition, paths, format }),
  }
}
