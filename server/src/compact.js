import {
  createCircuitContext,
  createConstructorContext,
  sampleContractAddress,
} from '@deployseal/deployseal-contract/runtime'
import { Contract, ledger } from '@deployseal/deployseal-contract/contract'
import { configuredPolicySalt, operationId, operationNullifier, sha256Hex } from './protocol.js'

function uint16(value, name) {
  if (!Number.isInteger(value) || value < 0 || value > 65_535) {
    throw new Error(`${name} must be an integer from 0 through 65535`)
  }
  return BigInt(value)
}

async function simulator(policy, evidence) {
  const privateState = {
    policy: {
      criticalCves: uint16(evidence.criticalCves, 'evidence.criticalCves'),
      maxCriticalCves: uint16(policy.maxCriticalCves, 'policy.maxCriticalCves'),
      highCves: uint16(evidence.highCves, 'evidence.highCves'),
      maxHighCves: uint16(policy.maxHighCves, 'policy.maxHighCves'),
      evalScore: uint16(evidence.evalScore, 'evidence.evalScore'),
      minEvalScore: uint16(policy.minEvalScore, 'policy.minEvalScore'),
      approvalCount: uint16(new Set(evidence.approvalRoles).size, 'evidence.approvalRoles'),
      minimumApprovals: uint16(policy.minimumApprovals, 'policy.minimumApprovals'),
    },
    salt: configuredPolicySalt(),
  }
  const contract = new Contract({
    privatePolicy: ({ privateState: state }) => [state, state.policy],
    privatePolicySalt: ({ privateState: state }) => [state, state.salt],
  })
  const initial = await contract.initialState(createConstructorContext(privateState, '0'.repeat(64)))
  const context = createCircuitContext(
    sampleContractAddress(),
    initial.currentZswapLocalState,
    initial.currentContractState,
    initial.currentPrivateState,
  )
  return { contract, context, initialLedger: ledger(context.currentQueryContext.state) }
}

function gasCost(value) {
  return Object.fromEntries(Object.entries(value).map(([key, amount]) => [key, String(amount)]))
}

export async function verifyLocalCompactProof({ core, policy, evidence }) {
  const { contract, context, initialLedger } = await simulator(policy, evidence)
  const nullifier = operationNullifier(core)
  const result = await contract.impureCircuits.reserve(
    context,
    initialLedger.policyRoot,
    nullifier,
    Buffer.from(operationId(core), 'hex'),
    uint16(core.policyEpoch, 'core.policyEpoch'),
  )

  return {
    status: 'verified',
    kind: 'compact-local-simulator',
    policyRoot: Buffer.from(initialLedger.policyRoot).toString('hex'),
    nullifier: nullifier.toString('hex'),
    hash: sha256Hex(Buffer.concat([initialLedger.policyRoot, nullifier])),
    gasCost: gasCost(result.gasCost),
  }
}

export async function finalizeLocalCompactReceipt({ core, policy, evidence, receiptHash, proof }) {
  if (!/^[0-9a-f]{64}$/u.test(receiptHash)) throw new Error('receipt hash must be 32-byte lowercase hex')
  const { contract, context, initialLedger } = await simulator(policy, evidence)
  const nullifier = operationNullifier(core)
  const policyRoot = Buffer.from(initialLedger.policyRoot).toString('hex')
  if (proof?.policyRoot && proof.policyRoot !== policyRoot) throw new Error('Compact policy root changed')
  const reserved = await contract.impureCircuits.reserve(
    context,
    initialLedger.policyRoot,
    nullifier,
    Buffer.from(operationId(core), 'hex'),
    uint16(core.policyEpoch, 'core.policyEpoch'),
  )
  const result = await contract.impureCircuits.finalize(
    reserved.context,
    nullifier,
    Buffer.from(receiptHash, 'hex'),
  )
  return {
    status: 'verified',
    kind: 'compact-local-simulator',
    policyRoot,
    nullifier: nullifier.toString('hex'),
    receiptHash,
    gasCost: gasCost(result.gasCost),
  }
}
