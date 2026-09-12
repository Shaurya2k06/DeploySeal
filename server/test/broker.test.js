import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { DeploySealBroker } from '../src/broker.js'
import { DEMO_EVIDENCE, PRIVATE_POLICY, makeOperationCore, operationDigest, operationId } from '../src/protocol.js'

function makeBroker() {
  const directory = mkdtempSync(join(tmpdir(), 'deployseal-test-'))
  const broker = new DeploySealBroker({ statePath: join(directory, 'state.json') })
  return { broker, directory }
}

test('lost provider response recovers once with the same token and receipt', async () => {
  const { broker, directory } = makeBroker()
  try {
    const interrupted = await broker.start({ scenario: 'crash' })
    assert.equal(interrupted.accepted, true)
    assert.equal(interrupted.interrupted, true)
    assert.equal(interrupted.snapshot.operation.status, 'RECOVERY_REQUIRED')
    assert.equal(interrupted.snapshot.provider.effectCount, 1)

    const operationId = interrupted.snapshot.operation.operationId
    const recovered = await broker.recover()
    assert.equal(recovered.recovered, true)
    assert.equal(recovered.snapshot.operation.status, 'FINALIZED')
    assert.equal(recovered.snapshot.provider.effectCount, 1)
    assert.equal(recovered.snapshot.operation.provider.requestToken, operationId)
    assert.equal('targetId' in recovered.snapshot.operation, false)
    assert.equal('artifactDigest' in recovered.snapshot.operation, false)
    assert.equal('commitSha' in recovered.snapshot.operation, false)
    assert.equal('signature' in recovered.snapshot.operation.receipt, false)

    const receiptHash = recovered.snapshot.operation.receipt.hash
    const repeated = await broker.recover()
    assert.equal(repeated.idempotent, true)
    assert.equal(repeated.snapshot.operation.receipt.hash, receiptHash)

    const verified = await broker.verifyReceipt()
    assert.equal(verified.valid, true)

    const originalTarget = broker.currentOperation().receipt.actualTarget
    broker.currentOperation().receipt.actualTarget = 'tampered-target'
    assert.equal((await broker.verifyReceipt()).valid, false)
    broker.currentOperation().receipt.actualTarget = originalTarget

    const replay = await broker.replay()
    assert.equal(replay.accepted, false)
    assert.equal(replay.code, 'OPERATION_ALREADY_CONSUMED')
    assert.equal(replay.snapshot.provider.effectCount, 1)

    const invalid = await broker.start({ scenario: 'invalid' })
    assert.equal(invalid.accepted, false)
    assert.equal(invalid.code, 'POLICY_NOT_SATISFIED')
    assert.equal(invalid.snapshot.provider.effectCount, 1)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('unknown Midnight response resumes the same reserved operation', async () => {
  const { directory } = makeBroker()
  let proofCalls = 0
  const broker = new DeploySealBroker({
    statePath: join(directory, 'state.json'),
    proofVerifier: async ({ operationDigest }) => {
      proofCalls += 1
      if (proofCalls === 1) throw new Error('response lost')
      return { status: 'verified', kind: 'midnight-test', hash: operationDigest.toString('hex') }
    },
  })
  try {
    const interrupted = await broker.start({ scenario: 'happy' })
    assert.equal(interrupted.interrupted, true)
    assert.equal(interrupted.snapshot.operation.status, 'RECOVERY_REQUIRED')
    const operationId = interrupted.snapshot.operation.operationId
    const recovered = await broker.recover()
    assert.equal(recovered.snapshot.operation.status, 'FINALIZED')
    assert.equal(recovered.snapshot.operation.operationId, operationId)
    assert.equal(proofCalls, 2)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('the real crash seam loses the response before writing a provider checkpoint', async () => {
  const { directory } = makeBroker()
  let calls = 0
  const provider = {
    id: 'azure-arm',
    stackName: 'deployseal-demo-stack',
    capabilities: { nativeIdempotency: true, durableQueryByOperationId: true, receiptCanBindActualTargetAndDigest: true },
    async execute(input) {
      calls += 1
      return { providerOperationId: 'provider-1', actualTarget: input.operation.core.targetId, actualArtifactDigest: input.operation.core.artifactDigest, status: 'SUCCEEDED', completedAt: new Date().toISOString() }
    },
    async query(input) {
      calls += 1
      return { providerOperationId: 'provider-1', actualTarget: input.operation.core.targetId, actualArtifactDigest: input.operation.core.artifactDigest, status: 'SUCCEEDED', completedAt: new Date().toISOString() }
    },
  }
  const broker = new DeploySealBroker({
    statePath: join(directory, 'state.json'),
    provider,
    proofVerifier: async () => ({ status: 'verified', kind: 'midnight-test' }),
    policy: { ...PRIVATE_POLICY, allowedProviderId: provider.id },
    evidence: { ...DEMO_EVIDENCE, providerId: provider.id },
    crashProcess() { throw Object.assign(new Error('process would be killed here'), { code: 'RESPONSE_LOST' }) },
  })
  try {
    const interrupted = await broker.start({ scenario: 'crash' })
    assert.equal(interrupted.snapshot.operation.status, 'RECOVERY_REQUIRED')
    assert.equal(Object.keys(broker.state.provider.executions).length, 0)
    assert.equal((await broker.recover()).snapshot.operation.status, 'FINALIZED')
    assert.equal(calls, 2)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('receipt signing is durable before Midnight finalization', async () => {
  const { directory } = makeBroker()
  let finalizeCalls = 0
  let signCalls = 0
  const broker = new DeploySealBroker({
    statePath: join(directory, 'state.json'),
    proofVerifier: async () => ({ status: 'verified', kind: 'midnight-test' }),
    finalizeVerifier: async () => {
      finalizeCalls += 1
      if (finalizeCalls === 1) throw new Error('finalization response lost')
      return { status: 'verified', kind: 'midnight-test' }
    },
    receiptSigner: {
      id: 'test-kms',
      async sign(message) {
        signCalls += 1
        return message
      },
      async verify() {
        return true
      },
    },
  })
  try {
    await assert.rejects(broker.start({ scenario: 'happy' }), /finalization response lost/u)
    assert.equal(broker.currentOperation().status, 'RECEIPT_SIGNED')
    const receiptHash = broker.currentOperation().receiptHash
    const recovered = await broker.recover()
    assert.equal(recovered.snapshot.operation.status, 'FINALIZED')
    assert.equal(recovered.snapshot.operation.receipt.hash, receiptHash)
    assert.equal(signCalls, 1)
    assert.equal(finalizeCalls, 2)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('policy failure happens before provider invocation', async () => {
  const { broker, directory } = makeBroker()
  try {
    const result = await broker.start({ scenario: 'invalid' })
    assert.equal(result.accepted, false)
    assert.equal(result.code, 'POLICY_NOT_SATISFIED')
    assert.equal(result.snapshot.operation, null)
    assert.equal(result.snapshot.provider.effectCount, 0)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('operation identity is canonical and provider-safe', () => {
  const core = makeOperationCore({ nonce: '0123456789abcdef0123456789abcdef' })
  const digest = operationDigest(core).toString('hex')
  const id = operationId(core)
  assert.match(digest, /^[0-9a-f]{64}$/u)
  assert.equal(id, digest)
  assert.match(id, /^[A-Za-z0-9][-A-Za-z0-9]*$/u)
  assert.equal(id.length, 64)
})

test('audit disclosure returns only selected fields', async () => {
  const { broker, directory } = makeBroker()
  try {
    await broker.start({ scenario: 'happy' })
    const result = await broker.disclose(['policyEpoch', 'outcome', 'not-allowed'])
    assert.deepEqual(result.disclosure.fields, ['policyEpoch', 'outcome'])
    assert.deepEqual(Object.keys(result.disclosure.values), ['policyEpoch', 'outcome'])
    assert.equal(result.snapshot.auditCount, 1)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('SQLite state lease serializes separate broker workers and preserves checkpoints', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'deployseal-sqlite-'))
  const statePath = join(directory, 'state.sqlite')
  const first = new DeploySealBroker({ statePath })
  const second = new DeploySealBroker({ statePath })
  const events = []
  let entered
  const enteredPromise = new Promise((resolve) => { entered = resolve })
  let release
  const releasePromise = new Promise((resolve) => { release = resolve })
  try {
    const firstRun = first.exclusive(async () => {
      events.push('first-start')
      entered()
      await releasePromise
      first.state.lastAttempt = { type: 'first', status: 'complete', code: 'OK', at: new Date().toISOString() }
      first.save()
      events.push('first-end')
    })
    await enteredPromise
    const secondRun = second.exclusive(async () => {
      events.push('second-start')
      second.state.lastAttempt = { type: 'second', status: 'complete', code: 'OK', at: new Date().toISOString() }
      second.save()
      events.push('second-end')
    })
    await new Promise((resolve) => setTimeout(resolve, 100))
    assert.deepEqual(events, ['first-start'])
    release()
    await Promise.all([firstRun, secondRun])
    assert.deepEqual(events, ['first-start', 'first-end', 'second-start', 'second-end'])
    const reopened = new DeploySealBroker({ statePath })
    try {
      assert.equal(reopened.state.lastAttempt.type, 'second')
    } finally {
      reopened.close()
    }
  } finally {
    first.close()
    second.close()
    rmSync(directory, { recursive: true, force: true })
  }
})
