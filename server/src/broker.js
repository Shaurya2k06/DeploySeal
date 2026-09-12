import { generateKeyPairSync, sign, verify } from 'node:crypto'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import {
  DEMO_EVIDENCE,
  PRIVATE_POLICY,
  defaultPolicyRoot,
  encodeCanonical,
  evaluatePolicy,
  makeOperationCore,
  operationDigest,
  operationId,
  operationNullifier,
  permitHash,
  publicOperation,
  receiptHash,
  sha256Hex,
} from './protocol.js'

const DEFAULT_STATE_PATH = join(tmpdir(), 'deployseal-state.json')
const FINAL_STATES = new Set(['FINALIZED', 'FAILED'])

function now() {
  return new Date().toISOString()
}

function initialState() {
  const keyPair = generateKeyPairSync('ed25519')
  return {
    version: 1,
    policy: { epoch: PRIVATE_POLICY.epoch, root: defaultPolicyRoot() },
    operations: {},
    provider: { executions: {} },
    audit: [],
    lastAttempt: null,
    receiptKey: {
      id: 'local-kms-demo',
      privateKey: keyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }),
      publicKey: keyPair.publicKey.export({ format: 'pem', type: 'spki' }),
    },
  }
}

function publicAttempt(attempt) {
  if (!attempt) return null
  return {
    type: attempt.type,
    status: attempt.status,
    code: attempt.code,
    at: attempt.at,
  }
}

function addTimeline(operation, id, label, status = 'complete') {
  operation.timeline.push({ id, label, status, at: now() })
}

export class DeploySealBroker {
  constructor({ statePath = process.env.DEPLOYSEAL_STATE_PATH || DEFAULT_STATE_PATH } = {}) {
    this.statePath = statePath
    this.lock = Promise.resolve()
    this.state = this.load()
  }

  load() {
    if (!existsSync(this.statePath)) {
      const state = initialState()
      this.state = state
      this.save()
      return state
    }

    const state = JSON.parse(readFileSync(this.statePath, 'utf8'))
    if (!state.receiptKey?.privateKey || !state.receiptKey?.publicKey) {
      const fresh = initialState()
      state.receiptKey = fresh.receiptKey
      this.state = state
      this.save()
    }
    return state
  }

  save() {
    mkdirSync(dirname(this.statePath), { recursive: true })
    const tempPath = `${this.statePath}.tmp`
    writeFileSync(tempPath, JSON.stringify(this.state, null, 2), { mode: 0o600 })
    renameSync(tempPath, this.statePath)
  }

  exclusive(task) {
    // ponytail: one process-local queue; use a transactional database lock when multiple broker workers are deployed.
    const previous = this.lock
    let release
    this.lock = new Promise((resolve) => {
      release = resolve
    })
    const next = previous.catch(() => undefined).then(task)
    next.then(() => release(), () => release())
    return next
  }

  currentOperation() {
    const ids = Object.keys(this.state.operations)
    return ids.length ? this.state.operations[ids[ids.length - 1]] : null
  }

  snapshot() {
    const operation = this.currentOperation()
    const providerEffectCount = Object.keys(this.state.provider.executions).length

    return {
      mode: 'local-emulator',
      warning: 'Local demo only: Compact, AWS CloudFormation, Nitro, and KMS are emulated.',
      policy: this.state.policy,
      operation: operation
        ? {
            ...publicOperation(operation.core),
            status: operation.status,
            gates: operation.gates,
            timeline: operation.timeline,
            proof: operation.proof,
            provider: operation.provider
              ? {
                  operationId: operation.provider.providerOperationId,
                  requestToken: operation.operationId,
                  effectCount: providerEffectCount,
                }
              : { operationId: null, requestToken: operation.operationId, effectCount: providerEffectCount },
              receipt: operation.receipt
              ? {
                  hash: operation.receiptHash,
                  keyId: operation.receipt.receiptKeyId,
                  status: operation.receipt.status,
                }
              : null,
          }
        : null,
      provider: {
        id: 'aws-cloudformation-local',
        effectCount: providerEffectCount,
        executions: Object.values(this.state.provider.executions).map((execution) => ({
          operationId: execution.operationId,
          providerOperationId: execution.providerOperationId,
          status: execution.status,
        })),
      },
      lastAttempt: publicAttempt(this.state.lastAttempt),
      auditCount: this.state.audit.length,
    }
  }

  async start({ scenario = 'crash' } = {}) {
    return this.exclusive(async () => {
      const current = this.currentOperation()
      if (current && scenario !== 'invalid') return { accepted: false, code: 'OPERATION_EXISTS', snapshot: this.snapshot() }

      const core =
        scenario === 'invalid'
          ? makeOperationCore({ targetId: 'unauthorized-stack' })
          : makeOperationCore()
      const result = evaluatePolicy(core)
      if (!result.ok) {
        this.state.lastAttempt = {
          type: scenario,
          status: 'rejected',
          code: 'POLICY_NOT_SATISFIED',
          at: now(),
        }
        this.save()
        return { accepted: false, code: 'POLICY_NOT_SATISFIED', snapshot: this.snapshot() }
      }

      const digest = operationDigest(core)
      const id = digest.toString('hex')
      const policyRoot = this.state.policy.root
      const proofHash = sha256Hex(
        encodeCanonical(
          new Map([
            [1, digest],
            [2, Buffer.from(policyRoot, 'hex')],
            [3, result.gates.map(({ id: gateId, status }) => [gateId, status])],
          ]),
        ),
      )
      const operation = {
        core,
        operationId: id,
        operationDigest: digest.toString('hex'),
        operationNullifier: operationNullifier(core).toString('hex'),
        permitHash: permitHash(core).toString('hex'),
        status: 'RESERVED',
        gates: result.gates,
        proof: { status: 'verified', kind: 'local-policy-emulator', hash: proofHash },
        timeline: [],
        provider: null,
        receipt: null,
        receiptHash: null,
        receiptSignature: null,
        createdAt: now(),
      }
      addTimeline(operation, 'proof', 'Private policy proof accepted')
      addTimeline(operation, 'reserved', 'Midnight authorization reserved')
      this.state.operations[id] = operation
      this.save()

      operation.status = 'SUBMITTING'
      addTimeline(operation, 'submitting', 'Provider request persisted with operation token')
      this.save()

      try {
        const execution = this.executeProvider(operation, scenario === 'crash')
        this.finalize(operation, execution)
        this.save()
        return { accepted: true, snapshot: this.snapshot() }
      } catch (error) {
        if (error.code !== 'RESPONSE_LOST') throw error
        operation.status = 'RECOVERY_REQUIRED'
        addTimeline(operation, 'lost', 'Response lost after provider acceptance')
        this.state.lastAttempt = { type: 'crash', status: 'interrupted', code: 'RESPONSE_LOST', at: now() }
        this.save()
        return { accepted: true, interrupted: true, snapshot: this.snapshot() }
      }
    })
  }

  executeProvider(operation, loseResponse = false) {
    const existing = this.state.provider.executions[operation.operationId]
    if (existing) return { ...existing, reused: true }

    const execution = {
      operationId: operation.operationId,
      providerOperationId: `cf-local-${operation.operationId.slice(0, 12)}`,
      actualTarget: operation.core.targetId,
      actualArtifactDigest: operation.core.artifactDigest,
      status: 'SUCCEEDED',
      completedAt: now(),
    }
    this.state.provider.executions[operation.operationId] = execution
    this.save()

    if (loseResponse) {
      const error = new Error('provider accepted the operation but the response was lost')
      error.code = 'RESPONSE_LOST'
      throw error
    }
    return execution
  }

  finalize(operation, execution) {
    operation.provider = execution
    operation.status = 'PROVIDER_ACCEPTED'
    addTimeline(operation, 'provider-accepted', 'Provider reports one accepted effect')

    const receipt = {
      version: 1,
      operationDigest: operation.operationDigest,
      operationId: operation.operationId,
      permitHash: operation.permitHash,
      providerId: operation.core.providerId,
      providerOperationId: execution.providerOperationId,
      actualTarget: execution.actualTarget,
      actualArtifactDigest: execution.actualArtifactDigest,
      status: execution.status,
      providerCompletionTime: execution.completedAt,
      receiptKeyId: this.state.receiptKey.id,
      cloudTrailEventHash: sha256Hex(JSON.stringify(execution)),
      enclaveMeasurement: 'local-emulator',
    }
    const hash = receiptHash(receipt)
    const signature = sign(null, Buffer.from(hash, 'hex'), this.state.receiptKey.privateKey).toString('base64')
    operation.receipt = receipt
    operation.receiptHash = hash
    operation.receiptSignature = signature
    operation.status = 'RECEIPT_SIGNED'
    addTimeline(operation, 'receipt-signed', 'Receipt signed by local KMS emulator')
    operation.status = 'FINALIZED'
    addTimeline(operation, 'finalized', 'One receipt finalized')
  }

  async recover() {
    return this.exclusive(async () => {
      const operation = this.currentOperation()
      if (!operation) return { accepted: false, code: 'NO_OPERATION', snapshot: this.snapshot() }
      if (operation.status === 'FINALIZED') return { accepted: true, idempotent: true, snapshot: this.snapshot() }
      if (FINAL_STATES.has(operation.status)) {
        return { accepted: false, code: 'OPERATION_TERMINAL', snapshot: this.snapshot() }
      }
      if (!['RECOVERY_REQUIRED', 'SUBMITTING'].includes(operation.status)) {
        return { accepted: false, code: 'RECOVERY_NOT_ALLOWED', snapshot: this.snapshot() }
      }

      const execution = this.executeProvider(operation)
      addTimeline(operation, 'recovered', 'Recovered with the same provider token')
      this.finalize(operation, execution)
      this.state.lastAttempt = { type: 'recovery', status: 'completed', code: 'RECOVERED', at: now() }
      this.save()
      return { accepted: true, recovered: true, snapshot: this.snapshot() }
    })
  }

  async replay() {
    return this.exclusive(async () => {
      const operation = this.currentOperation()
      this.state.lastAttempt = {
        type: 'replay',
        status: 'rejected',
        code: operation ? 'OPERATION_ALREADY_CONSUMED' : 'NO_OPERATION',
        at: now(),
      }
      this.save()
      return {
        accepted: false,
        code: this.state.lastAttempt.code,
        snapshot: this.snapshot(),
      }
    })
  }

  async disclose(fields = []) {
    return this.exclusive(async () => {
      const operation = this.currentOperation()
      if (!operation) return { accepted: false, code: 'NO_OPERATION', snapshot: this.snapshot() }

      const allowed = {
        policyEpoch: operation.core.policyEpoch,
        operationId: operation.operationId,
        target: operation.core.targetId,
        artifactDigest: `sha256:${operation.core.artifactDigest}`,
        outcome: operation.status,
      }
      const selected = fields.filter((field) => Object.hasOwn(allowed, field))
      const values = Object.fromEntries(selected.map((field) => [field, allowed[field]]))
      const bundleHash = sha256Hex(
        Buffer.concat([
          Buffer.from('DeploySeal/DisclosureV1\0'),
          encodeCanonical(new Map(selected.map((field, index) => [index + 1, [field, values[field]]]))),
        ]),
      )
      this.state.audit.push({ fields: selected, bundleHash, at: now() })
      this.save()
      return {
        accepted: true,
        disclosure: { fields: selected, values, bundleHash, purpose: 'demo-audit' },
        snapshot: this.snapshot(),
      }
    })
  }

  async verifyReceipt() {
    return this.exclusive(async () => {
      const operation = this.currentOperation()
      if (!operation?.receipt || !operation.receiptHash || !operation.receiptSignature) {
        return { valid: false, code: 'NO_RECEIPT', snapshot: this.snapshot() }
      }
      const computedHash = receiptHash(operation.receipt)
      const hashMatches = computedHash === operation.receiptHash
      const signatureValid = verify(
        null,
        Buffer.from(computedHash, 'hex'),
        this.state.receiptKey.publicKey,
        Buffer.from(operation.receiptSignature, 'base64'),
      )
      return {
        valid: hashMatches && signatureValid,
        receiptHash: operation.receiptHash,
        keyId: this.state.receiptKey.id,
        snapshot: this.snapshot(),
      }
    })
  }

  async reset() {
    return this.exclusive(async () => {
      this.state = initialState()
      this.save()
      return this.snapshot()
    })
  }
}
