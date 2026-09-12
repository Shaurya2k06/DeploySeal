import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  CostModel,
  createCircuitContext,
  createConstructorContext,
  sampleContractAddress,
} from '@midnight-ntwrk/compact-runtime'
import { Contract, ledger } from '../src/managed/deployseal/contract/index.js'

const NULLIFIER = Uint8Array.from({ length: 32 }, (_, index) => 255 - index)
const SALT = Uint8Array.from({ length: 32 }, (_, index) => index + 33)

async function simulator(policy = { highCves: 1n, maxHighCves: 2n }, salt = SALT) {
  const contract = new Contract({
    privatePolicy: ({ privateState }) => [privateState, privateState.policy],
    privatePolicySalt: ({ privateState }) => [privateState, privateState.salt],
  })
  const initial = await contract.initialState(
    createConstructorContext({ policy, salt }, '0'.repeat(64)),
  )
  return {
    contract,
    context: createCircuitContext(
      'reserve',
      sampleContractAddress(),
      initial.currentZswapLocalState,
      initial.currentContractState,
      initial.currentPrivateState,
      undefined,
      undefined,
      CostModel.initialCostModel(),
    ),
  }
}

test('Compact reservation is bound to the private root and consumes a nullifier once', async () => {
  const { contract, context } = await simulator()
  const policyRoot = ledger(context.callContext.currentQueryContext.state).policyRoot
  const first = await contract.impureCircuits.reserve(context, policyRoot, NULLIFIER)
  const state = ledger(first.context.callContext.currentQueryContext.state)

  assert.equal(state.activePolicyEpoch, 1n)
  assert.equal(state.operationNullifiers.member(NULLIFIER), true)
  await assert.rejects(
    contract.impureCircuits.reserve(first.context, policyRoot, NULLIFIER),
    /Operation already reserved/u,
  )
})

test('Compact rejects a mismatched private policy witness', async () => {
  const { contract, context } = await simulator({ highCves: 3n, maxHighCves: 2n })
  const policyRoot = ledger(context.callContext.currentQueryContext.state).policyRoot

  await assert.rejects(
    contract.impureCircuits.reserve(context, policyRoot, NULLIFIER),
    /Private vulnerability threshold failed/u,
  )
})
