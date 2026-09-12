import { createHash, randomBytes } from 'node:crypto'
import { encode } from 'cbor2'

export const DOMAINS = Object.freeze({
  policy: 'DeploySeal/PolicyV1',
  operation: 'DeploySeal/OperationV1',
  nullifier: 'DeploySeal/OperationNullifierV1',
  receipt: 'DeploySeal/ReceiptV1',
  disclosure: 'DeploySeal/DisclosureV1',
})

const DEMO_SALT = Buffer.from('0123456789abcdef0123456789abcdef')
const DEMO_COMMIT = 'a'.repeat(40)
const DEMO_ARTIFACT_DIGEST = sha256Hex('deployseal-demo-artifact')

export const PRIVATE_POLICY = Object.freeze({
  version: 1,
  epoch: 1,
  allowedRepositoryId: 123456789,
  allowedWorkflow: 'deployseal-demo.yml',
  allowedProviderId: 'aws-cloudformation-local',
  allowedTargetId: 'deployseal-demo-stack',
  allowedRegion: 'us-east-1',
  maxCriticalCves: 0,
  maxHighCves: 2,
  minEvalScore: 90,
  requiredApprovalRoles: Object.freeze(['security', 'governance']),
  minimumApprovals: 2,
  permitTtlSeconds: 900,
})

export const DEMO_EVIDENCE = Object.freeze({
  repositoryId: PRIVATE_POLICY.allowedRepositoryId,
  workflow: PRIVATE_POLICY.allowedWorkflow,
  providerId: PRIVATE_POLICY.allowedProviderId,
  targetId: PRIVATE_POLICY.allowedTargetId,
  region: PRIVATE_POLICY.allowedRegion,
  artifactDigest: DEMO_ARTIFACT_DIGEST,
  commitSha: DEMO_COMMIT,
  criticalCves: 0,
  highCves: 1,
  evalScore: 97,
  approvalRoles: Object.freeze(['security', 'governance']),
})

function sha256(value) {
  return createHash('sha256').update(value).digest()
}

export function sha256Hex(value) {
  return sha256(value).toString('hex')
}

export function encodeCanonical(value) {
  return Buffer.from(encode(value, { cde: true, ignoreOriginalEncoding: true }))
}

function domainBytes(domain) {
  return Buffer.from(`${domain}\0`)
}

function bytes32(hex) {
  if (!/^[0-9a-f]{64}$/u.test(hex)) throw new Error('expected 32-byte lowercase hex')
  return Buffer.from(hex, 'hex')
}

function operationMap(core) {
  return new Map([
    [1, core.version],
    [2, core.providerId],
    [3, core.repositoryId],
    [4, core.runId],
    [5, core.runAttempt],
    [6, Buffer.from(core.commitSha, 'hex')],
    [7, bytes32(core.artifactDigest)],
    [8, core.targetId],
    [9, core.environmentId],
    [10, core.policyEpoch],
    [11, Buffer.from(core.nonce, 'hex')],
  ])
}

export function makeOperationCore(overrides = {}) {
  return {
    version: 1,
    providerId: PRIVATE_POLICY.allowedProviderId,
    repositoryId: DEMO_EVIDENCE.repositoryId,
    runId: 987654321,
    runAttempt: 1,
    commitSha: DEMO_COMMIT,
    artifactDigest: DEMO_EVIDENCE.artifactDigest,
    targetId: PRIVATE_POLICY.allowedTargetId,
    environmentId: 'staging',
    policyEpoch: PRIVATE_POLICY.epoch,
    nonce: randomBytes(16).toString('hex'),
    ...overrides,
  }
}

export function operationDigest(core) {
  return sha256(Buffer.concat([domainBytes(DOMAINS.operation), encodeCanonical(operationMap(core))]))
}

export function operationId(core) {
  return operationDigest(core).toString('hex')
}

export function operationNullifier(core) {
  return sha256(Buffer.concat([domainBytes(DOMAINS.nullifier), operationDigest(core)]))
}

function policyMap(policy) {
  return new Map([
    [1, policy.version],
    [2, policy.epoch],
    [3, policy.allowedRepositoryId],
    [4, policy.allowedWorkflow],
    [5, policy.allowedProviderId],
    [6, policy.allowedTargetId],
    [7, policy.allowedRegion],
    [8, policy.maxCriticalCves],
    [9, policy.maxHighCves],
    [10, policy.minEvalScore],
    [11, policy.requiredApprovalRoles],
    [12, policy.minimumApprovals],
    [13, policy.permitTtlSeconds],
  ])
}

export function policyRoot(policy = PRIVATE_POLICY, salt = DEMO_SALT) {
  return sha256(Buffer.concat([domainBytes(DOMAINS.policy), encodeCanonical(policyMap(policy)), salt])).toString('hex')
}

export function permitHash(core, policy = PRIVATE_POLICY) {
  return sha256(
    Buffer.concat([
      Buffer.from('DeploySeal/PermitV1\0'),
      operationDigest(core),
      bytes32(policyRoot(policy)),
    ]),
  )
}

function gate(id, label, ok) {
  return { id, label, status: ok ? 'verified' : 'failed' }
}

export function evaluatePolicy(core, evidence = DEMO_EVIDENCE, policy = PRIVATE_POLICY) {
  const gates = [
    gate(
      'provenance',
      'Artifact provenance',
      evidence.repositoryId === policy.allowedRepositoryId &&
        evidence.workflow === policy.allowedWorkflow &&
        evidence.commitSha === core.commitSha &&
        evidence.artifactDigest === core.artifactDigest,
    ),
    gate(
      'vulnerabilities',
      'Vulnerability budget',
      evidence.criticalCves <= policy.maxCriticalCves && evidence.highCves <= policy.maxHighCves,
    ),
    gate('evaluation', 'Model evaluation', evidence.evalScore >= policy.minEvalScore),
    gate(
      'target',
      'Target and residency',
      evidence.providerId === policy.allowedProviderId &&
        evidence.targetId === policy.allowedTargetId &&
        evidence.region === policy.allowedRegion &&
        core.targetId === policy.allowedTargetId,
    ),
    gate(
      'approvals',
      'Required approvals',
      policy.requiredApprovalRoles.every((role) => evidence.approvalRoles.includes(role)) &&
        new Set(evidence.approvalRoles).size >= policy.minimumApprovals,
    ),
  ]

  return { ok: gates.every(({ status }) => status === 'verified'), gates }
}

export function receiptMap(receipt) {
  return new Map([
    [1, receipt.version],
    [2, bytes32(receipt.operationDigest)],
    [3, receipt.operationId],
    [4, bytes32(receipt.permitHash)],
    [5, receipt.providerId],
    [6, receipt.providerOperationId],
    [7, receipt.actualTarget],
    [8, bytes32(receipt.actualArtifactDigest)],
    [9, receipt.status],
    [10, receipt.providerCompletionTime],
    [11, receipt.receiptKeyId],
    [12, bytes32(receipt.cloudTrailEventHash)],
    [13, receipt.enclaveMeasurement],
  ])
}

export function receiptHash(receipt) {
  return sha256(Buffer.concat([domainBytes(DOMAINS.receipt), encodeCanonical(receiptMap(receipt))])).toString('hex')
}

export function publicOperation(core) {
  return {
    operationId: operationId(core),
    operationDigest: operationDigest(core).toString('hex'),
    providerId: core.providerId,
    policyEpoch: core.policyEpoch,
  }
}

export function defaultPolicyRoot() {
  return policyRoot()
}

export function defaultArtifactDigest() {
  return DEMO_ARTIFACT_DIGEST
}
