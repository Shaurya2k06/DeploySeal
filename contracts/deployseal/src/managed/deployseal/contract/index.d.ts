import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export type Witnesses<PS> = {
  privatePolicy(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, { criticalCves: bigint,
                                                                              maxCriticalCves: bigint,
                                                                              highCves: bigint,
                                                                              maxHighCves: bigint,
                                                                              evalScore: bigint,
                                                                              minEvalScore: bigint,
                                                                              approvalCount: bigint,
                                                                              minimumApprovals: bigint
                                                                            }];
  privatePolicySalt(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
}

export type ImpureCircuits<PS> = {
  reserve(context: __compactRuntime.CircuitContext<PS>,
          operationPolicyRoot_0: Uint8Array,
          operationNullifier_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  finalize(context: __compactRuntime.CircuitContext<PS>,
           operationNullifier_0: Uint8Array,
           receiptHash_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
}

export type ProvableCircuits<PS> = {
  reserve(context: __compactRuntime.CircuitContext<PS>,
          operationPolicyRoot_0: Uint8Array,
          operationNullifier_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  finalize(context: __compactRuntime.CircuitContext<PS>,
           operationNullifier_0: Uint8Array,
           receiptHash_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
}

export type PureCircuits = {
}

export type Circuits<PS> = {
  reserve(context: __compactRuntime.CircuitContext<PS>,
          operationPolicyRoot_0: Uint8Array,
          operationNullifier_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  finalize(context: __compactRuntime.CircuitContext<PS>,
           operationNullifier_0: Uint8Array,
           receiptHash_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
}

export type Ledger = {
  readonly policyRoot: Uint8Array;
  readonly activePolicyEpoch: bigint;
  operationNullifiers: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: Uint8Array): boolean;
    [Symbol.iterator](): Iterator<Uint8Array>
  };
  finalizedNullifiers: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: Uint8Array): boolean;
    [Symbol.iterator](): Iterator<Uint8Array>
  };
  receiptHashes: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: Uint8Array): boolean;
    [Symbol.iterator](): Iterator<Uint8Array>
  };
}

export type ContractReferenceLocations = any;

export declare const contractReferenceLocations : ContractReferenceLocations;

export declare class Contract<PS = any, W extends Witnesses<PS> = Witnesses<PS>> {
  witnesses: W;
  circuits: Circuits<PS>;
  impureCircuits: ImpureCircuits<PS>;
  provableCircuits: ProvableCircuits<PS>;
  constructor(witnesses: W);
  initialState(context: __compactRuntime.ConstructorContext<PS>): __compactRuntime.ConstructorResult<PS>;
}

export declare function ledger(state: __compactRuntime.StateValue | __compactRuntime.ChargedState): Ledger;
export declare const pureCircuits: PureCircuits;
