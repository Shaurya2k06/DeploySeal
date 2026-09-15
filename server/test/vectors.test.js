import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  makeOperationCore,
  operationDigest,
  operationId,
  operationNullifier,
  permitHash,
  policyRoot,
} from '../src/protocol.js'

const policy = {
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
  requiredApprovalRoles: ['security', 'governance'],
  minimumApprovals: 2,
  permitTtlSeconds: 900,
}

const evidence = {
  repositoryId: policy.allowedRepositoryId,
  workflow: policy.allowedWorkflow,
  providerId: policy.allowedProviderId,
  targetId: policy.allowedTargetId,
  region: policy.allowedRegion,
  artifactDigest: 'aa00d9a6a33f7fb4a6c01011617f84a6f15432eb3166a5894370941a94b2b4fe',
  commitSha: 'a'.repeat(40),
  runId: 987654321,
  runAttempt: 1,
  environment: 'staging',
  criticalCves: 0,
  highCves: 1,
  evalScore: 97,
  approvalRoles: ['security', 'governance'],
}

const salt = Buffer.from('0123456789abcdef0123456789abcdef')

test('OperationV1 golden vector stays stable', () => {
  const core = makeOperationCore({
    runId: 42,
    runAttempt: 3,
    nonce: '0123456789abcdef0123456789abcdef',
  }, policy, evidence)

  assert.equal(operationDigest(core).toString('hex'), 'e4b0801144dc037239dfbb74fcb494fb128ccf69e812ca8bbce2022522fe8013')
  assert.equal(operationId(core), 'e4b0801144dc037239dfbb74fcb494fb128ccf69e812ca8bbce2022522fe8013')
  assert.equal(operationNullifier(core).toString('hex'), 'f3473bcf7434f749b3abd4b5296afeb8e8ea8f550721d284c8aa3b92cfee7a4f')
  assert.equal(policyRoot(policy, salt, evidence), '73f3fa5e28975304a43cf280073562aea17416aad6047935ec43debd511b6d7f')
  assert.equal(permitHash(core, policy, evidence, salt).toString('hex'), '152bd784db4467f11c0cd557d6c8aca515839af9e6f333117a151a32537e2f0e')
})
