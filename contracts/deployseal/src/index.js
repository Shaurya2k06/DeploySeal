import { CompactTypeUnsignedInteger, persistentCommit } from './runtime.js'

export * as DeploySeal from './managed/deployseal/contract/index.js'
export * from './runtime.js'

export const witnesses = {
  privatePolicy: ({ privateState }) => [privateState, privateState.policy],
  privatePolicySalt: ({ privateState }) => [privateState, privateState.salt],
}

const uint16 = new CompactTypeUnsignedInteger(65_535n, 2)
const privatePolicyFields = [
  'criticalCves',
  'maxCriticalCves',
  'highCves',
  'maxHighCves',
  'evalScore',
  'minEvalScore',
  'approvalCount',
  'minimumApprovals',
]
const privatePolicyType = {
  alignment: () => privatePolicyFields.slice(1).reduce((value) => value.concat(uint16.alignment()), uint16.alignment()),
  toValue: (value) => privatePolicyFields.slice(1).reduce((result, field) => result.concat(uint16.toValue(value[field])), uint16.toValue(value[privatePolicyFields[0]])),
}

export function privatePolicyRoot(policy, salt) {
  return persistentCommit(privatePolicyType, policy, salt)
}
