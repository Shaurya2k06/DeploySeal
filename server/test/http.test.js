import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

test('HTTP demo completes recovery and keeps the provider effect at one', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'deployseal-http-'))
  const previousStatePath = process.env.DEPLOYSEAL_STATE_PATH
  process.env.DEPLOYSEAL_STATE_PATH = join(directory, 'state.json')
  const { server } = await import('../src/index.js?http-test')

  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(0, '127.0.0.1', resolve)
    })
    const address = server.address()
    const base = `http://127.0.0.1:${address.port}`
    const post = async (path, body = {}) => {
      const response = await fetch(`${base}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      })
      return { status: response.status, body: await response.json() }
    }
    const get = async (path) => {
      const response = await fetch(`${base}${path}`)
      return { status: response.status, body: await response.json() }
    }
    const waitFor = async (predicate) => {
      for (let attempt = 0; attempt < 100; attempt += 1) {
        const result = await get('/api/release')
        if (predicate(result.body)) return result.body
        await new Promise((resolve) => setTimeout(resolve, 10))
      }
      throw new Error('timed out waiting for release state')
    }

    const start = await post('/api/release/start', { scenario: 'crash' })
    assert.equal(start.status, 202)
    assert.equal(start.body.code, 'OPERATION_ACCEPTED')
    assert.equal(typeof start.body.snapshot.operation.operationId, 'string')

    const afterStart = await waitFor((snapshot) => snapshot.operation.status === 'RECOVERY_REQUIRED')
    assert.equal(afterStart.operation.proof.kind, 'compact-local-simulator')
    assert.equal(afterStart.policy.root, afterStart.operation.proof.policyRoot)
    assert.equal(afterStart.provider.effectCount, 1)

    const recover = await post('/api/release/recover')
    assert.equal(recover.body.snapshot.operation.status, 'FINALIZED')
    assert.equal(recover.body.snapshot.provider.effectCount, 1)
    assert.equal((await post('/api/receipt/verify')).body.valid, true)
    const bundle = (await post('/api/receipt/export')).body.bundle
    assert.equal(typeof bundle.signature, 'string')
    assert.equal('privateKey' in bundle, false)
    assert.equal((await post('/api/release/replay')).body.code, 'OPERATION_ALREADY_CONSUMED')

    const disclosure = await post('/api/audit/disclose', { fields: ['policyEpoch', 'privatePolicy', 'outcome'] })
    assert.deepEqual(disclosure.body.disclosure.fields, ['policyEpoch', 'outcome'])
    assert.equal((await post('/api/reset')).body.snapshot.operation, null)
  } finally {
    await new Promise((resolve) => server.close(resolve))
    if (previousStatePath === undefined) delete process.env.DEPLOYSEAL_STATE_PATH
    else process.env.DEPLOYSEAL_STATE_PATH = previousStatePath
    rmSync(directory, { recursive: true, force: true })
  }
})
