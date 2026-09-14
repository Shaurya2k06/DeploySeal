import { generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import {
  DEMO_EVIDENCE,
  PRIVATE_POLICY,
  disclosureHash,
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
import { validateBuildFact } from './github.js'

const DEFAULT_STATE_PATH = join(tmpdir(), 'deployseal-state.json')
const FINAL_STATES = new Set(['FINALIZED', 'FAILED'])
const REQUIRED_PROVIDER_CAPABILITIES = [
  'nativeIdempotency',
  'durableQueryByOperationId',
  'receiptCanBindActualTargetAndDigest',
]

class SqliteStateStore {
  constructor(path) {
    mkdirSync(dirname(path), { recursive: true })
    this.db = new DatabaseSync(path)
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 1000;
      CREATE TABLE IF NOT EXISTS deployseal_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        payload TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS deployseal_lease (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        owner TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
    `)
    this.path = path
  }

  read() {
    const row = this.db.prepare('SELECT payload FROM deployseal_state WHERE id = 1').get()
    if (row) return JSON.parse(row.payload)

    // Keep an existing JSON state when an operator switches the live service
    // to SQLite; the legacy file remains as a recovery backup.
    const legacyPath = this.path.replace(/\.sqlite$/u, '.json')
    if (!existsSync(legacyPath)) return null
    const state = JSON.parse(readFileSync(legacyPath, 'utf8'))
    this.write(state)
    return state
  }

  write(state, owner = null) {
    this.db.exec('BEGIN IMMEDIATE')
    try {
      if (owner && !this.owns(owner)) throw Object.assign(new Error('SQLite state lease is not held'), { code: 'STATE_LEASE_LOST' })
      this.db.prepare(`
        INSERT INTO deployseal_state (id, payload) VALUES (1, ?)
        ON CONFLICT(id) DO UPDATE SET payload = excluded.payload
      `).run(JSON.stringify(state))
      this.db.exec('COMMIT')
    } catch (cause) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK')
      throw cause
    }
  }

  owns(owner) {
    const row = this.db.prepare('SELECT owner, expires_at FROM deployseal_lease WHERE id = 1').get()
    return row?.owner === owner && row.expires_at > Date.now()
  }

  async acquire(owner, timeoutMs = 300_000, leaseMs = 120_000) {
    const deadline = Date.now() + timeoutMs
    while (true) {
      try {
        this.db.exec('BEGIN IMMEDIATE')
        const lease = this.db.prepare('SELECT owner, expires_at FROM deployseal_lease WHERE id = 1').get()
        if (!lease || lease.expires_at <= Date.now() || lease.owner === owner) {
          this.db.prepare(`
            INSERT INTO deployseal_lease (id, owner, expires_at) VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET owner = excluded.owner, expires_at = excluded.expires_at
          `).run(owner, Date.now() + leaseMs)
          this.db.exec('COMMIT')
          return
        }
        this.db.exec('ROLLBACK')
      } catch (cause) {
        if (this.db.isTransaction) this.db.exec('ROLLBACK')
        if (Date.now() >= deadline) throw Object.assign(new Error('timed out acquiring SQLite state lease', { cause }), { code: 'STATE_LOCK_TIMEOUT' })
      }
      if (Date.now() >= deadline) throw Object.assign(new Error('timed out acquiring SQLite state lease'), { code: 'STATE_LOCK_TIMEOUT' })
      await new Promise((resolve) => setTimeout(resolve, 50))
    }
  }

  renew(owner, leaseMs = 120_000) {
    try {
      this.db.exec('BEGIN IMMEDIATE')
      const result = this.db.prepare('UPDATE deployseal_lease SET expires_at = ? WHERE id = 1 AND owner = ? AND expires_at > ?').run(Date.now() + leaseMs, owner, Date.now())
      this.db.exec('COMMIT')
      return result.changes === 1
    } catch {
      if (this.db.isTransaction) this.db.exec('ROLLBACK')
      return false
    }
  }

  release(owner) {
    this.db.exec('BEGIN IMMEDIATE')
    try {
      this.db.prepare('DELETE FROM deployseal_lease WHERE id = 1 AND owner = ?').run(owner)
      this.db.exec('COMMIT')
    } catch (cause) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK')
      throw cause
    }
  }
}

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
    attestationCheck = null,
    buildFact = null,
    crashProcess = process.env.DEPLOYSEAL_CRASH_MODE === 'kill' ? process.kill : null,
  } = {}) {
    this.statePath = statePath
    this.store = statePath.endsWith('.sqlite') ? new SqliteStateStore(statePath) : null
    this.leaseOwner = this.store ? `${process.pid}-${randomUUID()}` : null
    this.leaseMs = Number(process.env.DEPLOYSEAL_STATE_LEASE_MS || 120_000)
    this.leaseTimeoutMs = Number(process.env.DEPLOYSEAL_STATE_LOCK_TIMEOUT_MS || 300_000)
    if (!Number.isSafeInteger(this.leaseMs) || this.leaseMs < 10_000) throw new Error('DEPLOYSEAL_STATE_LEASE_MS must be at least 10000')
    if (!Number.isSafeInteger(this.leaseTimeoutMs) || this.leaseTimeoutMs < 1_000) throw new Error('DEPLOYSEAL_STATE_LOCK_TIMEOUT_MS must be at least 1000')
    this.policy = policy
    this.evidence = evidence
    this.providerAdapter = provider
    this.receiptSigner = receiptSigner
    this.proofVerifier = proofVerifier
    this.finalizeVerifier = finalizeVerifier
    this.attestationCheck = attestationCheck
    this.buildFact = buildFact
    this.crashProcess = crashProcess
    this.leaseHeld = false
    this.leaseLost = false
    if (this.providerAdapter) assertProviderCapabilities(this.providerAdapter)
    this.lock = Promise.resolve()
    this.state = this.load()
  }

  load() {
    const stored = this.store ? this.store.read() : existsSync(this.statePath) ? JSON.parse(readFileSync(this.statePath, 'utf8')) : null
    if (!stored) {
      const state = initialState(this.policy, this.evidence, this.receiptSigner)
      this.state = state
      this.save()
      return state
    }

    const state = stored
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
    if (this.store) {
      this.store.write(this.state, this.leaseHeld ? this.leaseOwner : null)
      return
    }
    mkdirSync(dirname(this.statePath), { recursive: true })
    const tempPath = `${this.statePath}.tmp`
    writeFileSync(tempPath, JSON.stringify(this.state, null, 2), { mode: 0o600 })
    renameSync(tempPath, this.statePath)
  }

  exclusive(task) {
    const previous = this.lock
    let release
    this.lock = new Promise((resolve) => {
      release = resolve
    })
    const next = previous.catch(() => undefined).then(async () => {
      if (!this.store) return task()
      await this.store.acquire(this.leaseOwner, this.leaseTimeoutMs, this.leaseMs)
      this.leaseHeld = true
      this.leaseLost = false
      const heartbeat = setInterval(() => {
        if (!this.store.renew(this.leaseOwner, this.leaseMs)) this.leaseLost = true
      }, Math.max(1_000, Math.floor(this.leaseMs / 3)))
      try {
        this.state = this.load()
        const result = await task()
        if (this.leaseLost) throw Object.assign(new Error('SQLite state lease was lost during the operation'), { code: 'STATE_LEASE_LOST' })
        return result
      } finally {
        clearInterval(heartbeat)
        this.leaseHeld = false
        if (!this.leaseLost) this.store.release(this.leaseOwner)
      }
    })
    next.then(() => release(), () => release())
    return next
  }

  currentOperation() {
    const ids = Object.keys(this.state.operations)
    return ids.length ? this.state.operations[ids[ids.length - 1]] : null
  }

  snapshot() {
    if (this.store && !this.leaseHeld) this.state = this.store.read() || this.state
    const operation = this.currentOperation()
    const providerEffectCount = Object.keys(this.state.provider.executions).length

    return {
      mode: this.providerAdapter?.mode || this.providerAdapter?.id || 'local-emulator',
      contractAddress: process.env.DEPLOYSEAL_MIDNIGHT_CONTRACT_ADDRESS || null,
      warning: this.providerAdapter
        ? `${this.providerAdapter.id} path: Compact proof verification, TEE isolation, and receipt-key policy are configured separately.`
        : 'Local demo only: Compact runs a local simulator; cloud provider, TEE, and receipt signing are emulated.',
      policy: this.state.policy,
      operation: operation
        ? {
            ...publicOperation(operation.core),
            status: operation.status,
            gates: operation.gates,
            timeline: operation.timeline,
            proof: operation.proof,
            finalizationTxHash: operation.compactFinalization?.txHash || null,
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

  async start({ scenario = 'crash', onAccepted = null } = {}) {
    return this.exclusive(async () => {
      const current = this.currentOperation()
      if (current && scenario !== 'invalid' && (!FINAL_STATES.has(current.status) || process.env.DEPLOYSEAL_ALLOW_NEW_OPERATION !== 'true')) {
        return { accepted: false, code: 'OPERATION_EXISTS', snapshot: this.snapshot() }
      }

      if (this.buildFact) {
        try {
          validateBuildFact(this.buildFact)
        } catch (cause) {
          this.state.lastAttempt = { type: scenario, status: 'rejected', code: cause.code || 'BUILD_FACT_INVALID', at: now() }
          this.save()
          return { accepted: false, code: cause.code || 'BUILD_FACT_INVALID', snapshot: this.snapshot() }
        }
      }

      const core =
        scenario === 'invalid'
          ? makeOperationCore({ targetId: 'unauthorized-stack' })
          : makeOperationCore({
              repositoryId: this.evidence.repositoryId,
              ...(this.evidence.runId === undefined ? {} : { runId: this.evidence.runId }),
              ...(this.evidence.runAttempt === undefined ? {} : { runAttempt: this.evidence.runAttempt }),
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
      if (this.attestationCheck) {
        try {
          await this.attestationCheck({ operationDigest: digest, operation: core })
        } catch {
          this.state.lastAttempt = { type: scenario, status: 'rejected', code: 'ATTESTATION_REQUIRED', at: now() }
          this.save()
          return { accepted: false, code: 'ATTESTATION_REQUIRED', snapshot: this.snapshot() }
        }
      }
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
      onAccepted?.(this.snapshot())

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
      if (loseResponse && this.crashProcess) {
        this.crashProcess(process.pid, 'SIGKILL')
        await new Promise(() => {})
      }
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
        (receipt.version >= 2 && receipt.actualTargetResourceId !== execution.actualTargetResourceId) ||
        receiptHash(receipt) !== hash
      ) {
        throw Object.assign(new Error('persisted receipt does not match the provider outcome'), {
          code: 'RECEIPT_BINDING_MISMATCH',
        })
      }
    } else {
      if (this.receiptSigner?.keyUrl) await this.receiptSigner.keyUrl()
      receipt = {
        version: execution.actualTargetResourceId ? 2 : 1,
        operationDigest: operation.operationDigest,
        operationId: operation.operationId,
        permitHash: operation.permitHash,
        providerId: operation.core.providerId,
        providerOperationId: execution.providerOperationId,
        actualTarget: execution.actualTarget,
        ...(execution.actualTargetResourceId ? { actualTargetResourceId: execution.actualTargetResourceId } : {}),
        actualArtifactDigest: execution.actualArtifactDigest,
        status: execution.status,
        providerCompletionTime: execution.completedAt,
        receiptKeyId: this.receiptSigner?.id || this.state.receiptKey.id,
        providerEvidenceHash: execution.providerEvidenceHash || execution.cloudTrailEventHash || sha256Hex(JSON.stringify(execution)),
        enclaveMeasurement:
          execution.enclaveMeasurement || (this.providerAdapter ? process.env.DEPLOYSEAL_ENCLAVE_MEASUREMENT || 'unconfigured' : 'local-emulator'),
      }
      hash = receiptHash(receipt)
      signature = this.receiptSigner
        ? (await this.receiptSigner.sign(Buffer.from(hash, 'hex'), receipt.receiptKeyId)).toString('base64')
        : sign(null, Buffer.from(hash, 'hex'), this.state.receiptKey.privateKey).toString('base64')
      operation.provider = execution
      operation.receipt = receipt
      operation.receiptHash = hash
      operation.receiptSignature = signature
      operation.status = 'RECEIPT_SIGNED'
      addTimeline(operation, 'provider-result', succeeded ? 'Provider reports one accepted effect' : 'Provider rejected the operation')
      addTimeline(operation, 'receipt-signed', this.receiptSigner ? `Receipt signed by ${this.providerAdapter?.id === 'azure-arm' ? 'Azure Key Vault' : 'AWS KMS'}` : 'Receipt signed by local key emulator')
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

  async recover({ onAccepted = null } = {}) {
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
      onAccepted?.(this.snapshot())

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

  async disclose(fields = [], { purpose = 'demo-audit', recipientId = 'audit-console' } = {}) {
    return this.exclusive(async () => {
      const operation = this.currentOperation()
      if (!operation?.receipt || operation.status !== 'FINALIZED') return { accepted: false, code: 'NO_FINALIZED_OPERATION', snapshot: this.snapshot() }
      if (typeof purpose !== 'string' || purpose.length < 1 || purpose.length > 128 || typeof recipientId !== 'string' || recipientId.length < 1 || recipientId.length > 128) {
        return { accepted: false, code: 'INVALID_DISCLOSURE_SCOPE', snapshot: this.snapshot() }
      }

      const allowed = {
        policyEpoch: operation.core.policyEpoch,
        operationId: operation.operationId,
        target: operation.core.targetId,
        artifactDigest: `sha256:${operation.core.artifactDigest}`,
        outcome: operation.status,
      }
      const selected = fields.filter((field, index) => Object.hasOwn(allowed, field) && fields.indexOf(field) === index)
      const values = Object.fromEntries(selected.map((field) => [field, allowed[field]]))
      const bundleHash = disclosureHash({
        operationId: operation.operationId,
        receiptHash: operation.receiptHash,
        purpose,
        recipientId,
        fields: selected,
        values,
      })
      const signature = this.receiptSigner
        ? (await this.receiptSigner.sign(Buffer.from(bundleHash, 'hex'), operation.receipt.receiptKeyId)).toString('base64')
        : sign(null, Buffer.from(bundleHash, 'hex'), this.state.receiptKey.privateKey).toString('base64')
      const keyId = operation.receipt.receiptKeyId || this.receiptSigner?.id || this.state.receiptKey.id
      this.state.audit.push({ fields: selected, bundleHash, signature, keyId, purpose, recipientId, at: now() })
      this.save()
      return {
        accepted: true,
        disclosure: { operationId: operation.operationId, receiptHash: operation.receiptHash, fields: selected, values, bundleHash, purpose, recipientId, signature, keyId },
        snapshot: this.snapshot(),
      }
    })
  }

  async verifyDisclosure(disclosure) {
    return this.exclusive(async () => {
      const operation = this.currentOperation()
      if (!operation?.receipt || !disclosure || disclosure.operationId !== operation.operationId || disclosure.receiptHash !== operation.receiptHash || !Array.isArray(disclosure.fields) || !disclosure.values || typeof disclosure.signature !== 'string') {
        return { valid: false, code: 'INVALID_DISCLOSURE_BUNDLE', snapshot: this.snapshot() }
      }
      if (
        typeof disclosure.purpose !== 'string' || disclosure.purpose.length < 1 || disclosure.purpose.length > 128 ||
        typeof disclosure.recipientId !== 'string' || disclosure.recipientId.length < 1 || disclosure.recipientId.length > 128 ||
        disclosure.keyId !== operation.receipt.receiptKeyId
      ) return { valid: false, code: 'INVALID_DISCLOSURE_SCOPE', snapshot: this.snapshot() }
      const allowed = {
        policyEpoch: operation.core.policyEpoch,
        operationId: operation.operationId,
        target: operation.core.targetId,
        artifactDigest: `sha256:${operation.core.artifactDigest}`,
        outcome: operation.status,
      }
      const selected = new Set()
      if (disclosure.fields.some((field) => !Object.hasOwn(allowed, field) || selected.has(field))) return { valid: false, code: 'INVALID_DISCLOSURE_SCOPE', snapshot: this.snapshot() }
      for (const field of disclosure.fields) {
        selected.add(field)
        if (!Object.hasOwn(disclosure.values, field) || disclosure.values[field] !== allowed[field]) return { valid: false, code: 'INVALID_DISCLOSURE_SCOPE', snapshot: this.snapshot() }
      }
      if (Object.keys(disclosure.values).some((field) => !selected.has(field))) return { valid: false, code: 'INVALID_DISCLOSURE_SCOPE', snapshot: this.snapshot() }
      const expectedHash = disclosureHash(disclosure)
      const signatureValid = this.receiptSigner
        ? await this.receiptSigner.verify(Buffer.from(expectedHash, 'hex'), Buffer.from(disclosure.signature, 'base64'), disclosure.keyId)
        : verify(null, Buffer.from(expectedHash, 'hex'), this.state.receiptKey.publicKey, Buffer.from(disclosure.signature, 'base64'))
      return { valid: expectedHash === disclosure.bundleHash && signatureValid, bundleHash: disclosure.bundleHash, keyId: disclosure.keyId, snapshot: this.snapshot() }
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
        ? await this.receiptSigner.verify(Buffer.from(computedHash, 'hex'), Buffer.from(operation.receiptSignature, 'base64'), operation.receipt.receiptKeyId)
        : verify(
            null,
            Buffer.from(computedHash, 'hex'),
            this.state.receiptKey.publicKey,
            Buffer.from(operation.receiptSignature, 'base64'),
          )
      return {
        valid: hashMatches && signatureValid,
        receiptHash: operation.receiptHash,
        keyId: operation.receipt.receiptKeyId || this.receiptSigner?.id || this.state.receiptKey.id,
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

  close() {
    this.store?.db.close()
  }
}
