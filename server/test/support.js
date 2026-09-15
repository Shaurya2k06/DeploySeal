import { generateKeyPairSync, sign, verify } from 'node:crypto'

export const TEST_POLICY = Object.freeze({
  version: 1,
  epoch: 1,
  allowedRepositoryId: 7,
  allowedWorkflow: 'test.yml',
  allowedProviderId: 'test-provider',
  allowedTargetId: 'test-target',
  allowedRegion: 'test-region',
  maxCriticalCves: 0,
  maxHighCves: 2,
  minEvalScore: 90,
  requiredApprovalRoles: Object.freeze(['security', 'governance']),
  minimumApprovals: 2,
  permitTtlSeconds: 900,
})

export const TEST_EVIDENCE = Object.freeze({
  repositoryId: TEST_POLICY.allowedRepositoryId,
  workflow: TEST_POLICY.allowedWorkflow,
  providerId: TEST_POLICY.allowedProviderId,
  targetId: TEST_POLICY.allowedTargetId,
  region: TEST_POLICY.allowedRegion,
  artifactDigest: 'c'.repeat(64),
  commitSha: 'b'.repeat(40),
  runId: 42,
  runAttempt: 1,
  environment: 'test',
  criticalCves: 0,
  highCves: 1,
  evalScore: 97,
  approvalRoles: Object.freeze(['security', 'governance']),
})

export const TEST_SALT = Buffer.alloc(32, 9)

export function testReceiptSigner() {
  const keyPair = generateKeyPairSync('ed25519')
  return {
    id: 'test-receipt-key',
    async sign(message) {
      return sign(null, message, keyPair.privateKey)
    },
    async verify(message, signature) {
      return verify(null, message, keyPair.publicKey, signature)
    },
  }
}

export function testProvider({ id = TEST_POLICY.allowedProviderId, stackName = TEST_POLICY.allowedTargetId } = {}) {
  return {
    id,
    stackName,
    capabilities: {
      nativeIdempotency: true,
      durableQueryByOperationId: true,
      receiptCanBindActualTargetAndDigest: true,
    },
    async execute({ operationId, operation }) {
      return {
        operationId,
        providerOperationId: `test-${operationId.slice(0, 12)}`,
        actualTarget: operation.core.targetId,
        actualArtifactDigest: operation.core.artifactDigest,
        status: 'SUCCEEDED',
        completedAt: new Date().toISOString(),
        providerEvidenceHash: 'd'.repeat(64),
        enclaveMeasurement: 'test-enclave',
      }
    },
    async query({ operationId, operation }) {
      return this.execute({ operationId, operation })
    },
  }
}

export function testProof() {
  return async ({ operationDigest }) => ({
    status: 'verified',
    kind: 'midnight-test',
    hash: operationDigest.toString('hex'),
  })
}

export function testFinalization() {
  return async () => ({ status: 'verified', kind: 'midnight-test' })
}

export function testBrokerOptions(statePath, overrides = {}) {
  return {
    statePath,
    policy: TEST_POLICY,
    evidence: TEST_EVIDENCE,
    policySalt: TEST_SALT,
    provider: testProvider(),
    receiptSigner: testReceiptSigner(),
    proofVerifier: testProof(),
    finalizeVerifier: testFinalization(),
    ...overrides,
  }
}
