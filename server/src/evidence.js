import { createPublicKey, sign, verify } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { DOMAINS, encodeCanonical, sha256Hex } from './protocol.js'

const KINDS = new Set(['sbom', 'model-eval', 'residency', 'approval'])
const HEX32 = /^[0-9a-f]{64}$/u

function failure(code, message) {
  return Object.assign(new Error(message), { code })
}

function requiredString(value, name, max = 256) {
  if (typeof value !== 'string' || value.length < 1 || value.length > max) throw failure('EVIDENCE_INVALID', `${name} is invalid`)
  return value
}

function bytes32(value, name) {
  if (!HEX32.test(value || '')) throw failure('EVIDENCE_INVALID', `${name} must be a 32-byte lowercase hex value`)
  return Buffer.from(value, 'hex')
}

function factMap(fact) {
  return new Map([
    [1, fact.version],
    [2, fact.kind],
    [3, fact.role],
    [4, fact.schemaId],
    [5, fact.schemaVersion],
    [6, bytes32(fact.subjectArtifactDigest, 'subjectArtifactDigest')],
    [7, fact.operationScope],
    [8, fact.issuedAt],
    [9, fact.expiresAt],
    [10, bytes32(fact.payloadCommitment, 'payloadCommitment')],
    [11, bytes32(fact.evidenceCiphertextHash, 'evidenceCiphertextHash')],
    [12, fact.signerKeyId],
  ])
}

export function evidenceFactDigest(fact) {
  return Buffer.from(sha256Hex(Buffer.concat([Buffer.from(`${DOMAINS.evidence}\0`), encodeCanonical(factMap(fact))])), 'hex')
}

export function signEvidenceFact(fact, privateKey) {
  if (!privateKey) throw failure('EVIDENCE_SIGNER', 'evidence signing key is required')
  return { ...fact, signature: sign(null, evidenceFactDigest(fact), privateKey).toString('base64') }
}

export function validateEvidenceFact(fact, expected = {}, now = Math.floor(Date.now() / 1000), skew = 60) {
  if (fact?.version !== 1 || !KINDS.has(fact.kind)) throw failure('EVIDENCE_INVALID', 'unsupported EvidenceFactV1 kind')
  requiredString(fact.role, 'role')
  requiredString(fact.schemaId, 'schemaId')
  if (!Number.isSafeInteger(fact.schemaVersion) || fact.schemaVersion < 1) throw failure('EVIDENCE_INVALID', 'schemaVersion is invalid')
  bytes32(fact.subjectArtifactDigest, 'subjectArtifactDigest')
  bytes32(fact.payloadCommitment, 'payloadCommitment')
  bytes32(fact.evidenceCiphertextHash, 'evidenceCiphertextHash')
  requiredString(fact.signerKeyId, 'signerKeyId')
  if (typeof fact.signature !== 'string' || !fact.signature) throw failure('EVIDENCE_SIGNATURE', 'evidence signature is required')
  if (!Number.isFinite(fact.issuedAt) || !Number.isFinite(fact.expiresAt) || fact.expiresAt <= fact.issuedAt) {
    throw failure('EVIDENCE_TIME_INVALID', 'evidence validity bounds are invalid')
  }
  if (fact.issuedAt > now + skew || fact.expiresAt < now - skew) throw failure('EVIDENCE_EXPIRED', 'evidence fact is outside its validity window')

  const scope = fact.operationScope
  if (!scope || typeof scope !== 'object') throw failure('EVIDENCE_SCOPE', 'evidence operation scope is required')
  for (const name of ['providerId', 'targetId', 'region']) requiredString(scope[name], `operationScope.${name}`)
  if (!Number.isSafeInteger(scope.policyEpoch) || scope.policyEpoch < 1) throw failure('EVIDENCE_SCOPE', 'operationScope.policyEpoch is invalid')
  const checks = [
    ['subjectArtifactDigest', fact.subjectArtifactDigest, expected.artifactDigest],
    ['commitSha', scope.commitSha, expected.commitSha],
    ['providerId', scope.providerId, expected.providerId],
    ['targetId', scope.targetId, expected.targetId],
    ['region', scope.region, expected.region],
    ['policyEpoch', scope.policyEpoch, expected.policyEpoch],
  ]
  if (checks.some(([, actual, wanted]) => wanted !== undefined && String(actual) !== String(wanted))) {
    throw failure('EVIDENCE_BINDING_MISMATCH', 'evidence fact is bound to a different release')
  }
  return fact
}

export function verifyEvidenceFact(fact, publicKey, expected = {}, now = Math.floor(Date.now() / 1000)) {
  validateEvidenceFact(fact, expected, now)
  if (!publicKey) throw failure('EVIDENCE_KEY', `no trusted key for ${fact.signerKeyId}`)
  try {
    if (!verify(null, evidenceFactDigest(fact), publicKey, Buffer.from(fact.signature, 'base64'))) {
      throw failure('EVIDENCE_SIGNATURE', 'evidence signature is invalid')
    }
  } catch (cause) {
    if (cause.code === 'EVIDENCE_SIGNATURE') throw cause
    throw failure('EVIDENCE_SIGNATURE', 'evidence signature is invalid')
  }
  return true
}

function keyFor(publicKeys, signerKeyId) {
  if (publicKeys && typeof publicKeys === 'object' && !publicKeys.type) return publicKeys[signerKeyId]
  return publicKeys
}

export function verifyEvidenceBundle(bundle, publicKeys, expected = {}, now = Math.floor(Date.now() / 1000)) {
  if (bundle?.version !== 1 || !Array.isArray(bundle.facts)) throw failure('EVIDENCE_BUNDLE_INVALID', 'EvidenceFact bundle is invalid')
  const seenKinds = new Set()
  const seenKeys = new Set()
  const approvals = new Set()
  for (const fact of bundle.facts) {
    if (seenKeys.has(fact?.signerKeyId)) throw failure('EVIDENCE_KEY_REUSE', 'evidence signer keys must be unique')
    seenKeys.add(fact?.signerKeyId)
    verifyEvidenceFact(fact, keyFor(publicKeys, fact.signerKeyId), expected, now)
    if (fact.kind === 'approval') {
      if (approvals.has(fact.role)) throw failure('EVIDENCE_APPROVAL_REUSE', 'approval roles must be unique')
      approvals.add(fact.role)
    } else if (seenKinds.has(fact.kind)) {
      throw failure('EVIDENCE_KIND_DUPLICATE', 'non-approval evidence kinds must be unique')
    } else {
      seenKinds.add(fact.kind)
    }
  }
  for (const kind of ['sbom', 'model-eval', 'residency', 'approval']) {
    if (!bundle.facts.some((fact) => fact.kind === kind)) throw failure('EVIDENCE_MISSING', `missing ${kind} evidence fact`)
  }
  if (approvals.size < 1) throw failure('EVIDENCE_MISSING', 'at least one approval fact is required')
  return bundle.facts
}

export function evidenceFromFacts(facts) {
  return {
    signedEvidenceFacts: facts.map(({ kind, role, schemaId, schemaVersion, signerKeyId, issuedAt, expiresAt }) => ({
      kind,
      role,
      schemaId,
      schemaVersion,
      signerKeyId,
      issuedAt,
      expiresAt,
    })),
  }
}

function configuredPublicKeys(raw) {
  if (!raw) throw failure('EVIDENCE_KEY', 'evidence verification key is required')
  try {
    const parsed = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not a key map')
    return Object.fromEntries(Object.entries(parsed).map(([id, value]) => [id, createPublicKey(value)]))
  } catch {
    try {
      return createPublicKey(raw)
    } catch (cause) {
      throw failure('EVIDENCE_KEY', 'evidence verification key is invalid')
    }
  }
}

export function configuredEvidenceFacts() {
  const rawBundle = process.env.DEPLOYSEAL_EVIDENCE_FACTS_JSON ||
    (process.env.DEPLOYSEAL_EVIDENCE_FACTS_FILE ? readFileSync(process.env.DEPLOYSEAL_EVIDENCE_FACTS_FILE, 'utf8') : null)
  const rawKey = process.env.DEPLOYSEAL_EVIDENCE_ADAPTER_PUBLIC_KEY ||
    (process.env.DEPLOYSEAL_EVIDENCE_ADAPTER_PUBLIC_KEY_FILE ? readFileSync(process.env.DEPLOYSEAL_EVIDENCE_ADAPTER_PUBLIC_KEY_FILE, 'utf8') : null)
  if (!rawBundle && !rawKey) throw failure('EVIDENCE_CONFIG', 'EvidenceFact bundle and verification key are required')
  if (!rawBundle || !rawKey) throw failure('EVIDENCE_CONFIG', 'both EvidenceFact bundle and verification key are required')
  let bundle
  try {
    bundle = JSON.parse(rawBundle)
  } catch {
    throw failure('EVIDENCE_CONFIG', 'EvidenceFact bundle must contain valid JSON')
  }
  return { bundle, publicKeys: configuredPublicKeys(rawKey) }
}
