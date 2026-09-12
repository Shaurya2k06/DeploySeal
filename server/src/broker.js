import { generateKeyPairSync, sign, verify } from 'node:crypto'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import {
  DEMO_EVIDENCE,
  PRIVATE_POLICY,
  encodeCanonical,
  evaluatePolicy,
  makeOperationCore,
  operationDigest,
  operationId,
  operationNullifier,
  permitHash,
  policyRoot,
  publicOperation,
  receiptHash,
  sha256Hex,
} from './protocol.js'

const DEFAULT_STATE_PATH = join(tmpdir(), 'deployseal-state.json')
const FINAL_STATES = new Set(['FINALIZED', 'FAILED'])
const REQUIRED_PROVIDER_CAPABILITIES = [
  'nativeIdempotency',
  'durableQueryByOperationId',
  'receiptCanBindActualTargetAndDigest',
]

function now() {
  return new Date().toISOString()
}

function initialState(policy, evidence, receiptSigner = null) {
  const keyPair = receiptSigner ? null : generateKeyPairSync('ed25519')
  return {
    version: 1,
    policy: { epoch: policy.epoch, root: policyRoot(policy, undefined, evidence) },
    operations: {},
    provider: { executions: {} },
    audit: [],
    lastAttempt: null,
    receiptKey: {
      id: receiptSigner?.id || 'local-kms-demo',
      privateKey: keyPair ? keyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }) : null,
      publicKey: keyPair ? keyPair.publicKey.export({ format: 'pem', type: 'spki' }) : null,
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

function assertProviderCapabilities(provider) {
  if (!provider?.capabilities || REQUIRED_PROVIDER_CAPABILITIES.some((name) => provider.capabilities[name] !== true)) {
    throw Object.assign(new Error('provider does not satisfy the DeploySeal recovery contract'), {
      code: 'PROVIDER_CAPABILITIES',
    })
  }
}

export class DeploySealBroker {
  constructor({
    statePath = process.env.DEPLOYSEAL_STATE_PATH || DEFAULT_STATE_PATH,
    policy = PRIVATE_POLICY,
    evidence = DEMO_EVIDENCE,
    provider = null,
    receiptSigner = null,
    proofVerifier = null,
    finalizeVerifier = null,
  } = {}) {
    this.statePath = statePath
    this.policy = policy
    this.evidence = evidence
    this.providerAdapter = provider
    this.receiptSigner = receiptSigner
    this.proofVerifier = proofVerifier
    this.finalizeVerifier = finalizeVerifier
    if (this.providerAdapter) assertProviderCapabilities(this.providerAdapter)
    this.lock = Promise.resolve()
    this.state = this.load()
  }

  load() {
    if (!existsSync(this.statePath)) {
      const state = initialState(this.policy, this.evidence, this.receiptSigner)
      this.state = state
      this.save()
      return state
    }

    const state = JSON.parse(readFileSync(this.statePath, 'utf8'))
    const expectedPolicy = { epoch: this.policy.epoch, root: policyRoot(this.policy, undefined, this.evidence) }
    let stateChanged = false
    if (state.policy?.epoch !== expectedPolicy.epoch || state.policy?.root !== expectedPolicy.root) {
      if (Object.keys(state.operations || {}).length) {
        throw Object.assign(new Error('durable state belongs to a different policy root'), {
          code: 'POLICY_STATE_MISMATCH',
        })
      }
      state.policy = expectedPolicy
      stateChanged = true
    }
    state.provider ||= { executions: {} }
    if (!state.provider.executions) {
      state.provider.executions = {}
      stateChanged = true
    }
    if (this.receiptSigner) {
      if (state.receiptKey?.privateKey && Object.keys(state.operations || {}).length) {
        throw Object.assign(new Error('durable state belongs to a different receipt-key mode'), {
          code: 'RECEIPT_KEY_MODE_MISMATCH',
        })
      }
      state.receiptKey = { id: this.receiptSigner.id, privateKey: null, publicKey: null }
      this.state = state
      this.save()
    } else if (!state.receiptKey?.privateKey || !state.receiptKey?.publicKey) {
      const fresh = initialState(this.policy, this.evidence)
      state.receiptKey = fresh.receiptKey
      this.state = state
      this.save()
    }
    if (stateChanged) {
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
      mode: this.providerAdapter ? 'aws-cloudformation' : 'local-emulator',
      warning: this.providerAdapter
        ? 'AWS path: Compact proof verification, Nitro isolation, and receipt-key policy must be configured separately.'
        : 'Local demo only: Compact runs a local simulator; AWS CloudFormation, Nitro, and KMS are emulated.',
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
        id: this.providerAdapter?.id || 'aws-cloudformation-local',
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

  async prove(operation, digest, proofHash) {
    const proof = this.proofVerifier
      ? await this.proofVerifier({
          core: operation.core,
          operationDigest: digest,
          policyRoot: this.state.policy.root,
          policy: this.policy,
          evidence: this.evidence,
        })
      : { status: 'verified', kind: 'local-policy-emulator', hash: proofHash }
    if (!proof || proof.status !== 'verified') return null
    if (proof.policyRoot && proof.policyRoot !== this.state.policy.root) {
      throw Object.assign(new Error('Midnight proof uses a different policy root'), { code: 'POLICY_ROOT_MISMATCH' })
    }
    return { ...proof, hash: proof.hash || proofHash }
  }

  async start({ scenario = 'crash' } = {}) {
    return this.exclusive(async () => {
      const current = this.currentOperation()
      if (current && scenario !== 'invalid') return { accepted: false, code: 'OPERATION_EXISTS', snapshot: this.snapshot() }

      const core =
        scenario === 'invalid'
          ? makeOperationCore({ targetId: 'unauthorized-stack' })
          : makeOperationCore({
              repositoryId: this.evidence.repositoryId,
              commitSha: this.evidence.commitSha,
              artifactDigest: this.evidence.artifactDigest,
              providerId: this.providerAdapter?.id || this.policy.allowedProviderId,
              targetId: this.providerAdapter?.stackName || this.policy.allowedTargetId,
            })
      const result = evaluatePolicy(core, this.evidence, this.policy)
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

      if (this.providerAdapter && !this.proofVerifier) {
        this.state.lastAttempt = { type: scenario, status: 'rejected', code: 'PROOF_REQUIRED', at: now() }
        this.save()
        return { accepted: false, code: 'PROOF_REQUIRED', snapshot: this.snapshot() }
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
        permitHash: permitHash(core, this.policy, this.evidence).toString('hex'),
        status: this.proofVerifier ? 'PROOF_SUBMITTING' : 'RESERVED',
        gates: result.gates,
        proof: this.proofVerifier ? { status: 'pending', kind: 'midnight-authorization', hash: proofHash } : await this.prove({ core }, digest, proofHash),
        timeline: [],
        provider: null,
        receipt: null,
        receiptHash: null,
        receiptSignature: null,
        createdAt: now(),
      }
      if (this.proofVerifier) {
        addTimeline(operation, 'proof-submitting', 'Private policy proof is being submitted')
      } else {
        addTimeline(operation, 'proof', 'Private policy proof accepted')
        addTimeline(operation, 'reserved', 'Midnight authorization reserved')
      }
      this.state.operations[id] = operation
      this.save()

      if (this.proofVerifier) {
        let proof
        try {
          proof = await this.prove(operation, digest, proofHash)
        } catch (error) {
          operation.status = 'RECOVERY_REQUIRED'
          addTimeline(operation, 'proof-unknown', 'Midnight response is unknown; recovery required')
          this.state.lastAttempt = { type: scenario, status: 'interrupted', code: 'PROOF_RESPONSE_UNKNOWN', at: now() }
          this.save()
          return { accepted: true, interrupted: true, snapshot: this.snapshot() }
        }
        if (!proof) {
          delete this.state.operations[id]
          this.state.lastAttempt = { type: scenario, status: 'rejected', code: 'PROOF_NOT_VERIFIED', at: now() }
          this.save()
          return { accepted: false, code: 'PROOF_NOT_VERIFIED', snapshot: this.snapshot() }
        }
        operation.proof = proof
        operation.status = 'RESERVED'
        addTimeline(operation, 'proof', 'Private policy proof accepted')
        addTimeline(operation, 'reserved', 'Midnight authorization reserved')
        this.save()
      }

      operation.status = 'SUBMITTING'
      addTimeline(operation, 'submitting', 'Provider request persisted with operation token')
      this.save()

      try {
        const execution = await this.executeProvider(operation, scenario === 'crash')
        if (execution.status === 'PENDING') {
          operation.status = 'RECOVERY_REQUIRED'
          addTimeline(operation, 'provider-pending', 'Provider accepted; waiting for durable outcome')
          this.state.lastAttempt = { type: 'provider', status: 'interrupted', code: 'PROVIDER_PENDING', at: now() }
          this.save()
          return { accepted: true, interrupted: true, snapshot: this.snapshot() }
        }
        await this.finalize(operation, execution)
        this.save()
        return { accepted: true, snapshot: this.snapshot() }
      } catch (error) {
        if (error.code !== 'RESPONSE_LOST' && !this.providerAdapter) throw error
        operation.status = 'RECOVERY_REQUIRED'
        addTimeline(operation, 'lost', this.providerAdapter ? 'Provider response is unknown; recovery required' : 'Response lost after provider acceptance')
        this.state.lastAttempt = {
          type: scenario,
          status: 'interrupted',
          code: error.code === 'RESPONSE_LOST' ? 'RESPONSE_LOST' : 'PROVIDER_RESPONSE_UNKNOWN',
          at: now(),
        }
        this.save()
        return { accepted: true, interrupted: true, snapshot: this.snapshot() }
      }
    })
  }

  async executeProvider(operation, loseResponse = false) {
    const existing = this.state.provider.executions[operation.operationId]
    if (existing && (!this.providerAdapter || existing.status !== 'PENDING')) return { ...existing, reused: true }

    if (this.providerAdapter) {
      const execution = await this.providerAdapter.execute({
        operationId: operation.operationId,
        operation,
      })
      const persisted = { ...execution, operationId: operation.operationId }
      this.state.provider.executions[operation.operationId] = persisted
      this.save()
      if (loseResponse) {
        const lost = new Error('provider accepted the operation but the response was lost')
        lost.code = 'RESPONSE_LOST'
        throw lost
      }
      return persisted
    }

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

  async finalize(operation, execution) {
    if (
      execution.actualTarget !== operation.core.targetId ||
      execution.actualArtifactDigest !== operation.core.artifactDigest
    ) {
      throw Object.assign(new Error('provider receipt does not match the reserved operation'), {
        code: 'RECEIPT_BINDING_MISMATCH',
      })
    }

    const succeeded = execution.status === 'SUCCEEDED'
    let receipt = operation.receipt
    let hash = operation.receiptHash
    let signature = operation.receiptSignature

    if (receipt) {
      if (
        typeof signature !== 'string' ||
        receipt.providerOperationId !== execution.providerOperationId ||
        receipt.status !== execution.status ||
        receipt.providerCompletionTime !== execution.completedAt ||
        receipt.actualTarget !== execution.actualTarget ||
        receipt.actualArtifactDigest !== execution.actualArtifactDigest ||
        receiptHash(receipt) !== hash
      ) {
        throw Object.assign(new Error('persisted receipt does not match the provider outcome'), {
          code: 'RECEIPT_BINDING_MISMATCH',
        })
      }
    } else {
      receipt = {
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
        receiptKeyId: this.receiptSigner?.id || this.state.receiptKey.id,
        cloudTrailEventHash: execution.cloudTrailEventHash || sha256Hex(JSON.stringify(execution)),
        enclaveMeasurement:
          execution.enclaveMeasurement || (this.providerAdapter ? process.env.DEPLOYSEAL_ENCLAVE_MEASUREMENT || 'unconfigured' : 'local-emulator'),
      }
      hash = receiptHash(receipt)
      signature = this.receiptSigner
        ? (await this.receiptSigner.sign(Buffer.from(hash, 'hex'))).toString('base64')
        : sign(null, Buffer.from(hash, 'hex'), this.state.receiptKey.privateKey).toString('base64')
      operation.provider = execution
      operation.receipt = receipt
      operation.receiptHash = hash
      operation.receiptSignature = signature
      operation.status = 'RECEIPT_SIGNED'
      addTimeline(operation, 'provider-result', succeeded ? 'Provider reports one accepted effect' : 'Provider rejected the operation')
      addTimeline(operation, 'receipt-signed', this.receiptSigner ? 'Receipt signed by AWS KMS' : 'Receipt signed by local KMS emulator')
      this.save()
    }

    if (this.finalizeVerifier) {
      if (!operation.compactFinalization) {
        const finalization = await this.finalizeVerifier({
          core: operation.core,
          evidence: this.evidence,
          operation,
          policy: this.policy,
          proof: operation.proof,
          receipt,
          receiptHash: hash,
          policyRoot: this.state.policy.root,
        })
        if (!finalization || finalization.status !== 'verified') {
          throw Object.assign(new Error('Compact receipt finalization was not verified'), {
            code: 'COMPACT_FINALIZE_FAILED',
          })
        }
        operation.compactFinalization = { ...finalization, receiptHash: hash }
        addTimeline(operation, 'midnight-finalized', 'Midnight receipt hash finalized')
        this.save()
      }
    }
    if (operation.status !== 'FINALIZED' && operation.status !== 'FAILED') {
      operation.status = succeeded ? 'FINALIZED' : 'FAILED'
      addTimeline(operation, 'finalized', succeeded ? 'One receipt finalized' : 'Failure receipt finalized')
      this.save()
    }
  }

  async recover() {
    return this.exclusive(async () => {
      const operation = this.currentOperation()
      if (!operation) return { accepted: false, code: 'NO_OPERATION', snapshot: this.snapshot() }
      if (operation.status === 'FINALIZED') return { accepted: true, idempotent: true, snapshot: this.snapshot() }
      if (FINAL_STATES.has(operation.status)) {
        return { accepted: false, code: 'OPERATION_TERMINAL', snapshot: this.snapshot() }
      }
      if (!['PROOF_SUBMITTING', 'RECOVERY_REQUIRED', 'SUBMITTING', 'RECEIPT_SIGNED'].includes(operation.status)) {
        return { accepted: false, code: 'RECOVERY_NOT_ALLOWED', snapshot: this.snapshot() }
      }

      if (['PROOF_SUBMITTING', 'RECOVERY_REQUIRED'].includes(operation.status) && operation.proof?.status !== 'verified') {
        if (!this.proofVerifier) {
          return { accepted: false, code: 'PROOF_REQUIRED', snapshot: this.snapshot() }
        }
        let proof
        try {
          proof = await this.prove(
            operation,
            Buffer.from(operation.operationDigest, 'hex'),
            operation.proof?.hash || sha256Hex(operation.operationDigest),
          )
        } catch {
          operation.status = 'RECOVERY_REQUIRED'
          if (!operation.timeline.some(({ id }) => id === 'proof-unknown')) {
            addTimeline(operation, 'proof-unknown', 'Midnight response is unknown; recovery required')
          }
          this.state.lastAttempt = { type: 'recovery', status: 'waiting', code: 'PROOF_RESPONSE_UNKNOWN', at: now() }
          this.save()
          return { accepted: true, pending: true, snapshot: this.snapshot() }
        }
        if (!proof) {
          operation.status = 'FAILED'
          this.state.lastAttempt = { type: 'recovery', status: 'rejected', code: 'PROOF_NOT_VERIFIED', at: now() }
          this.save()
          return { accepted: false, code: 'PROOF_NOT_VERIFIED', snapshot: this.snapshot() }
        }
        operation.proof = proof
        operation.status = 'RESERVED'
        addTimeline(operation, 'proof', 'Private policy proof accepted')
        addTimeline(operation, 'reserved', 'Midnight authorization reserved')
        if (!operation.timeline.some(({ id }) => id === 'submitting')) {
          operation.status = 'SUBMITTING'
          addTimeline(operation, 'submitting', 'Provider request persisted with operation token')
        }
        this.save()
      }

      let execution
      if (operation.status === 'RECEIPT_SIGNED') {
        execution = operation.provider
      } else if (this.providerAdapter) {
        const queried = await this.providerAdapter.query({
          operationId: operation.operationId,
          operation,
        })
        if (queried) {
          execution = { ...queried, operationId: operation.operationId }
          this.state.provider.executions[operation.operationId] = execution
          this.save()
        }
      }
      if (!execution) execution = await this.executeProvider(operation)
      if (execution.status === 'PENDING') {
        operation.status = 'RECOVERY_REQUIRED'
        this.state.lastAttempt = { type: 'recovery', status: 'waiting', code: 'PROVIDER_PENDING', at: now() }
        this.save()
        return { accepted: true, pending: true, snapshot: this.snapshot() }
      }
      addTimeline(operation, 'recovered', 'Recovered with the same provider token')
      await this.finalize(operation, execution)
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
      const signatureValid = this.receiptSigner
        ? await this.receiptSigner.verify(Buffer.from(computedHash, 'hex'), Buffer.from(operation.receiptSignature, 'base64'))
        : verify(
            null,
            Buffer.from(computedHash, 'hex'),
            this.state.receiptKey.publicKey,
            Buffer.from(operation.receiptSignature, 'base64'),
          )
      return {
        valid: hashMatches && signatureValid,
        receiptHash: operation.receiptHash,
        keyId: this.receiptSigner?.id || this.state.receiptKey.id,
        snapshot: this.snapshot(),
      }
    })
  }

  async receiptBundle() {
    return this.exclusive(async () => {
      const operation = this.currentOperation()
      if (!operation?.receipt || !operation.receiptHash || !operation.receiptSignature) {
        return { accepted: false, code: 'NO_RECEIPT', snapshot: this.snapshot() }
      }
      return {
        accepted: true,
        bundle: {
          receipt: operation.receipt,
          receiptHash: operation.receiptHash,
          signature: operation.receiptSignature,
          publicKey: this.receiptSigner ? null : this.state.receiptKey.publicKey,
          keyId: operation.receipt.receiptKeyId,
        },
      }
    })
  }

  async reset() {
    return this.exclusive(async () => {
      if (this.providerAdapter) {
        return { accepted: false, code: 'RESET_DISABLED_FOR_REAL_PROVIDER', snapshot: this.snapshot() }
      }
      this.state = initialState(this.policy, this.evidence, this.receiptSigner)
      this.save()
      return this.snapshot()
    })
  }
}
