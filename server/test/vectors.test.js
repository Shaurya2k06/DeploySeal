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

test('OperationV1 golden vector stays stable', () => {
  const core = makeOperationCore({
    runId: 42,
    runAttempt: 3,
    nonce: '0123456789abcdef0123456789abcdef',
  })

  assert.equal(operationDigest(core).toString('hex'), 'e4b0801144dc037239dfbb74fcb494fb128ccf69e812ca8bbce2022522fe8013')
  assert.equal(operationId(core), 'e4b0801144dc037239dfbb74fcb494fb128ccf69e812ca8bbce2022522fe8013')
  assert.equal(operationNullifier(core).toString('hex'), 'f3473bcf7434f749b3abd4b5296afeb8e8ea8f550721d284c8aa3b92cfee7a4f')
  assert.equal(policyRoot(), '73f3fa5e28975304a43cf280073562aea17416aad6047935ec43debd511b6d7f')
  assert.equal(permitHash(core).toString('hex'), '152bd784db4467f11c0cd557d6c8aca515839af9e6f333117a151a32537e2f0e')
})
