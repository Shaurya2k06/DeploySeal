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
  assert.equal(policyRoot(), 'fbdf69e98b83d9e1c29979bd7562b4fb01cb07498d4f24f7eeb651624224ac42')
  assert.equal(permitHash(core).toString('hex'), '93d1c7bebeb38a5c1bbcfd540576bb8e54945aa6cc9a1467a65c52f413a70ed7')
})
