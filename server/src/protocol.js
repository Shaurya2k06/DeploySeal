import { createHash, randomBytes } from 'node:crypto'
import { encode } from 'cbor2'
import { privatePolicyRoot as compactPrivatePolicyRoot } from '@deployseal/deployseal-contract'

export const DOMAINS = Object.freeze({
  policy: 'DeploySeal/PolicyV1',
  evidence: 'DeploySeal/EvidenceV1',
  approval: 'DeploySeal/ApprovalV1',
  build: 'DeploySeal/BuildFactV1',
  operation: 'DeploySeal/OperationV1',
  nullifier: 'DeploySeal/OperationNullifierV1',
  intent: 'DeploySeal/IntentNullifierV1',
  lease: 'DeploySeal/BrokerLeaseV1',
  receipt: 'DeploySeal/ReceiptV1',
  disclosure: 'DeploySeal/DisclosureV1',
})

export function configuredPolicySalt() {
  const value = process.env.DEPLOYSEAL_PRIVATE_POLICY_SALT_HEX
  if (!value) throw new Error('DEPLOYSEAL_PRIVATE_POLICY_SALT_HEX is required')
  if (!/^[0-9a-f]{64}$/u.test(value)) throw new Error('DEPLOYSEAL_PRIVATE_POLICY_SALT_HEX must be 32-byte lowercase hex')
  return Buffer.from(value, 'hex')
}

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

export function makeOperationCore(overrides = {}, policy, evidence) {
  if (!policy || !evidence) throw new Error('policy and evidence are required to build an operation')
  return {
    version: 1,
    providerId: policy.allowedProviderId,
    repositoryId: evidence.repositoryId,
    runId: evidence.runId,
    runAttempt: evidence.runAttempt ?? 1,
    commitSha: evidence.commitSha,
    artifactDigest: evidence.artifactDigest,
    targetId: policy.allowedTargetId,
    environmentId: evidence.environment || 'production',
    policyEpoch: policy.epoch,
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

function compactPrivatePolicy(policy, evidence) {
  return {
    criticalCves: BigInt(evidence.criticalCves),
    maxCriticalCves: BigInt(policy.maxCriticalCves),
    highCves: BigInt(evidence.highCves),
    maxHighCves: BigInt(policy.maxHighCves),
    evalScore: BigInt(evidence.evalScore),
    minEvalScore: BigInt(policy.minEvalScore),
    approvalCount: BigInt(new Set(evidence.approvalRoles).size),
    minimumApprovals: BigInt(policy.minimumApprovals),
  }
}

export function policyRoot(policy, salt = configuredPolicySalt(), evidence) {
  if (!policy || !evidence) throw new Error('policy and evidence are required to calculate a policy root')
  return Buffer.from(compactPrivatePolicyRoot(compactPrivatePolicy(policy, evidence), salt)).toString('hex')
}

export function permitHash(core, policy, evidence, salt = configuredPolicySalt()) {
  if (!policy || !evidence) throw new Error('policy and evidence are required to calculate a permit hash')
  return sha256(
    Buffer.concat([
      Buffer.from('DeploySeal/PermitV1\0'),
      operationDigest(core),
      bytes32(policyRoot(policy, salt, evidence)),
    ]),
  )
}

function gate(id, label, ok) {
  return { id, label, status: ok ? 'verified' : 'failed' }
}

export function evaluatePolicy(core, evidence, policy) {
  if (!policy || !evidence) throw new Error('policy and evidence are required to evaluate an operation')
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
  const entries = [
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
    [12, bytes32(receipt.providerEvidenceHash || receipt.cloudTrailEventHash)],
    [13, receipt.enclaveMeasurement],
  ]
  if (receipt.version >= 2) entries.push([14, receipt.actualTargetResourceId])
  return new Map(entries)
}

export function receiptHash(receipt) {
  return sha256(Buffer.concat([domainBytes(DOMAINS.receipt), encodeCanonical(receiptMap(receipt))])).toString('hex')
}

export function disclosureHash({ operationId: id, receiptHash: hash, purpose, recipientId, fields, values }) {
  return sha256(
    Buffer.concat([
      domainBytes(DOMAINS.disclosure),
      encodeCanonical(new Map([
        [1, id],
        [2, bytes32(hash)],
        [3, purpose],
        [4, recipientId],
        [5, fields.map((field, index) => [index + 1, [field, values[field]]])],
      ])),
    ]),
  ).toString('hex')
}

export function publicOperation(core) {
  return {
    operationId: operationId(core),
    operationDigest: operationDigest(core).toString('hex'),
    providerId: core.providerId,
    policyEpoch: core.policyEpoch,
  }
}
