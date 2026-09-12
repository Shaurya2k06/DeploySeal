import assert from 'node:assert/strict'
import { generateKeyPairSync, sign, verify } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  DescribeChangeSetCommand,
  ExecuteChangeSetCommand,
} from '@aws-sdk/client-cloudformation'
import { LookupEventsCommand } from '@aws-sdk/client-cloudtrail'
import { SignCommand, VerifyCommand } from '@aws-sdk/client-kms'
import { test } from 'node:test'
import { AwsCloudFormationProvider, AwsKmsReceiptSigner } from '../src/aws.js'
import { DeploySealBroker } from '../src/broker.js'
import { DEMO_EVIDENCE, PRIVATE_POLICY } from '../src/protocol.js'

const operationId = 'b'.repeat(64)
const operation = { core: { targetId: 'deployseal-demo-stack', artifactDigest: 'c'.repeat(64) } }

test('broker rejects providers without recovery capabilities', () => {
  assert.throws(
    () => new DeploySealBroker({ provider: { id: 'unsafe-provider' } }),
    /provider does not satisfy the DeploySeal recovery contract/u,
  )
})

test('CloudFormation adapter reuses the operation token and binds terminal evidence', async () => {
  const calls = []
  const client = {
    async send(command) {
      calls.push(command)
      if (command instanceof ExecuteChangeSetCommand) return { StackId: 'stack-1' }
      if (command instanceof DescribeChangeSetCommand) {
        return {
          StackId: 'stack-1',
          StackName: 'deployseal-demo-stack',
          ChangeSetId: 'change-set-1',
          ExecutionStatus: 'EXECUTE_COMPLETE',
          LastUpdatedTime: new Date('2026-09-12T00:00:00.000Z'),
          Parameters: [{ ParameterKey: 'DeploySealArtifactDigest', ParameterValue: `sha256:${operation.core.artifactDigest}` }],
        }
      }
      throw new Error('unexpected CloudFormation command')
    },
  }
  const cloudTrailClient = {
    async send(command) {
      assert.equal(command instanceof LookupEventsCommand, true)
      return {
        Events: [{
          EventId: 'event-1',
          EventTime: '2026-09-12T00:00:30.000Z',
          CloudTrailEvent: JSON.stringify({ requestParameters: { clientRequestToken: operationId } }),
        }],
      }
    },
  }
  const provider = new AwsCloudFormationProvider({
    region: 'us-east-1',
    stackName: 'deployseal-demo-stack',
    changeSetName: 'deployseal-demo-change-set',
    client,
    cloudTrailClient,
    now: () => Date.parse('2026-09-12T00:01:00.000Z'),
  })

  const accepted = await provider.execute({ operationId, operation })
  const result = await provider.query({ operationId, operation })

  assert.equal(calls[0].input.ClientRequestToken, operationId)
  assert.equal(accepted.status, 'PENDING')
  assert.equal(result.status, 'SUCCEEDED')
  assert.equal(result.providerOperationId, 'stack-1')
  assert.equal(result.actualTarget, operation.core.targetId)
  assert.equal(result.actualArtifactDigest, operation.core.artifactDigest)
  assert.equal(result.cloudTrailEventId, 'event-1')
  assert.equal(result.completedAt, '2026-09-12T00:00:30.000Z')
})

test('KMS signer delegates signing and verification without exporting a private key', async () => {
  const calls = []
  const client = {
    async send(command) {
      calls.push(command)
      if (command instanceof SignCommand) return { Signature: Uint8Array.from([1, 2, 3]) }
      if (command instanceof VerifyCommand) return { SignatureValid: true }
      throw new Error('unexpected KMS command')
    },
  }
  const signer = new AwsKmsReceiptSigner({ region: 'us-east-1', keyId: 'alias/deployseal', client })
  const message = Buffer.from('receipt')
  const signature = await signer.sign(message)

  assert.deepEqual(signature, Buffer.from([1, 2, 3]))
  assert.equal(await signer.verify(message, signature), true)
  assert.equal(calls[0].input.KeyId, 'alias/deployseal')
  assert.equal(calls[0].input.MessageType, 'RAW')
  assert.equal(calls[1].input.Signature.length, 3)
})

test('broker production seam recovers a pending CloudFormation result once', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'deployseal-aws-'))
  const keyPair = generateKeyPairSync('ed25519')
  const providerCalls = []
  const provider = {
    id: 'aws-cloudformation',
    stackName: 'deployseal-demo-stack',
    capabilities: {
      nativeIdempotency: true,
      durableQueryByOperationId: true,
      receiptCanBindActualTargetAndDigest: true,
    },
    async execute(input) {
      providerCalls.push(['execute', input.operationId])
      return {
        providerOperationId: 'stack-1',
        actualTarget: input.operation.core.targetId,
        actualArtifactDigest: input.operation.core.artifactDigest,
        status: 'PENDING',
      }
    },
    async query(input) {
      providerCalls.push(['query', input.operationId])
      return {
        providerOperationId: 'stack-1',
        actualTarget: input.operation.core.targetId,
        actualArtifactDigest: input.operation.core.artifactDigest,
        status: 'SUCCEEDED',
        completedAt: '2026-09-12T00:00:00.000Z',
        cloudTrailEventHash: 'd'.repeat(64),
      }
    },
  }
  const receiptSigner = {
    id: 'alias/deployseal',
    async sign(message) {
      return sign(null, message, keyPair.privateKey)
    },
    async verify(message, signature) {
      return verify(null, message, keyPair.publicKey, signature)
    },
  }
  const policy = { ...PRIVATE_POLICY, allowedProviderId: provider.id }
  const evidence = { ...DEMO_EVIDENCE, providerId: provider.id }
  const broker = new DeploySealBroker({
    statePath: join(directory, 'state.json'),
    policy,
    evidence,
    provider,
    receiptSigner,
    proofVerifier: async () => ({ status: 'verified', kind: 'fake-midnight-proof', hash: 'e'.repeat(64) }),
  })

  try {
    assert.equal(JSON.parse(readFileSync(join(directory, 'state.json'), 'utf8')).receiptKey.privateKey, null)
    const started = await broker.start({ scenario: 'happy' })
    assert.equal(started.snapshot.operation.status, 'RECOVERY_REQUIRED')
    const recovered = await broker.recover()
    assert.equal(recovered.snapshot.operation.status, 'FINALIZED')
    assert.equal(recovered.snapshot.provider.effectCount, 1)
    assert.deepEqual(providerCalls.map(([type]) => type), ['execute', 'query'])
    assert.equal(recovered.snapshot.operation.receipt.keyId, 'alias/deployseal')
    assert.equal((await broker.verifyReceipt()).valid, true)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})
