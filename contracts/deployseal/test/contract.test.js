import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  createCircuitContext,
  createConstructorContext,
  sampleContractAddress,
} from '@midnight-ntwrk/compact-runtime'
import { Contract, ledger } from '../src/managed/deployseal/contract/index.js'

const NULLIFIER = Uint8Array.from({ length: 32 }, (_, index) => 255 - index)
const OPERATION_DIGEST = Uint8Array.from({ length: 32 }, (_, index) => index + 1)
const SALT = Uint8Array.from({ length: 32 }, (_, index) => index + 33)

async function simulator(policy = {}, salt = SALT) {
  const privatePolicy = {
    criticalCves: 0n,
    maxCriticalCves: 0n,
    highCves: 1n,
    maxHighCves: 2n,
    evalScore: 97n,
    minEvalScore: 90n,
    approvalCount: 2n,
    minimumApprovals: 2n,
    ...policy,
  }
  const contract = new Contract({
    privatePolicy: ({ privateState }) => [privateState, privateState.policy],
    privatePolicySalt: ({ privateState }) => [privateState, privateState.salt],
  })
  const initial = await contract.initialState(
    createConstructorContext({ policy: privatePolicy, salt }, '0'.repeat(64)),
  )
  return {
    contract,
    context: createCircuitContext(
      sampleContractAddress(),
      initial.currentZswapLocalState,
      initial.currentContractState,
      initial.currentPrivateState,
    ),
  }
}

test('Compact reservation is bound to the private root and consumes a nullifier once', async () => {
  const { contract, context } = await simulator()
  const policyRoot = ledger(context.currentQueryContext.state).policyRoot
  const first = await contract.impureCircuits.reserve(context, policyRoot, NULLIFIER, OPERATION_DIGEST, 1n)
  const state = ledger(first.context.currentQueryContext.state)

  assert.equal(state.activePolicyEpoch, 1n)
  assert.equal(state.operationNullifiers.member(NULLIFIER), true)
  assert.equal(Buffer.from(state.operationDigests.lookup(NULLIFIER)).equals(Buffer.from(OPERATION_DIGEST)), true)
  assert.throws(
    () => contract.impureCircuits.reserve(first.context, policyRoot, NULLIFIER, OPERATION_DIGEST, 1n),
    /Operation already reserved/u,
  )
})

test('Compact rejects a mismatched private policy witness', async () => {
  const { contract, context } = await simulator({ highCves: 3n, maxHighCves: 2n })
  const policyRoot = ledger(context.currentQueryContext.state).policyRoot

  assert.throws(
    () => contract.impureCircuits.reserve(context, policyRoot, NULLIFIER, OPERATION_DIGEST, 1n),
    /Private vulnerability threshold failed/u,
  )
})

test('Compact rejects private evaluation and approval failures', async () => {
  for (const [field, value, message] of [
    ['evalScore', 89n, 'Private evaluation threshold failed'],
    ['approvalCount', 1n, 'Private approval quorum failed'],
  ]) {
    const { contract, context } = await simulator({ [field]: value })
    const policyRoot = ledger(context.currentQueryContext.state).policyRoot
    assert.throws(
      () => contract.impureCircuits.reserve(context, policyRoot, NULLIFIER, OPERATION_DIGEST, 1n),
      new RegExp(message, 'u'),
    )
  }
})

test('Compact rejects a stale public policy epoch', async () => {
  const { contract, context } = await simulator()
  const policyRoot = ledger(context.currentQueryContext.state).policyRoot
  assert.throws(
    () => contract.impureCircuits.reserve(context, policyRoot, NULLIFIER, OPERATION_DIGEST, 2n),
    /Policy epoch mismatch/u,
  )
})

test('Compact finalizes a reserved operation once', async () => {
  const { contract, context } = await simulator()
  const policyRoot = ledger(context.currentQueryContext.state).policyRoot
  const reserved = await contract.impureCircuits.reserve(context, policyRoot, NULLIFIER, OPERATION_DIGEST, 1n)
  const finalized = await contract.impureCircuits.finalize(
    reserved.context,
    NULLIFIER,
    Uint8Array.from({ length: 32 }, (_, index) => index + 1),
  )
  const state = ledger(finalized.context.currentQueryContext.state)

  assert.equal(state.finalizedNullifiers.member(NULLIFIER), true)
  assert.equal(state.receiptHashes.size(), 1n)
  assert.equal(Buffer.from(state.receiptHashesByOperation.lookup(NULLIFIER)).equals(Buffer.from(Uint8Array.from({ length: 32 }, (_, index) => index + 1))), true)
  assert.throws(
    () => contract.impureCircuits.finalize(finalized.context, NULLIFIER, new Uint8Array(32)),
    /Operation already finalized/u,
  )
})
