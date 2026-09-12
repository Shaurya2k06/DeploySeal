import { createHash, createPublicKey, sign, verify } from 'node:crypto'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { DOMAINS, encodeCanonical, sha256Hex } from './protocol.js'

const execFileAsync = promisify(execFile)
const GITHUB_OIDC_ISSUER = 'https://token.actions.githubusercontent.com'

function failure(code, message) {
  return Object.assign(new Error(message), { code })
}

function decodePart(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(value)) throw failure('INVALID_JWT', 'malformed GitHub OIDC token')
  try {
    return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'))
  } catch {
    throw failure('INVALID_JWT', 'malformed GitHub OIDC token')
  }
}

export function decodeJwt(token) {
  const parts = typeof token === 'string' ? token.split('.') : []
  if (parts.length !== 3) throw failure('INVALID_JWT', 'malformed GitHub OIDC token')
  const header = decodePart(parts[0])
  const payload = decodePart(parts[1])
  if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object') {
    throw failure('INVALID_JWT', 'malformed GitHub OIDC token')
  }
  return {
    header,
    payload,
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: Buffer.from(parts[2], 'base64url'),
  }
}

function same(actual, expected) {
  return expected === undefined || String(actual) === String(expected)
}

function audienceIncludes(audience, expected) {
  if (expected === undefined) return true
  return Array.isArray(audience) ? audience.some((value) => same(value, expected)) : same(audience, expected)
}

export function validateGithubClaims(claims, expected = {}, now = Math.floor(Date.now() / 1000), skew = 60) {
  const issuer = expected.issuer || GITHUB_OIDC_ISSUER
  if (!expected.audience) throw failure('OIDC_AUDIENCE_CONFIG', 'GitHub OIDC audience is required')
  const required = ['iss', 'aud', 'repository_id', 'workflow', 'workflow_ref', 'sha', 'run_id', 'run_attempt']
  if (required.some((name) => claims?.[name] === undefined || claims?.[name] === null || claims?.[name] === '')) {
    throw failure('OIDC_CLAIM_REQUIRED', 'GitHub OIDC token is missing a required claim')
  }
  const checks = [
    ['issuer', claims.iss, issuer],
    ['audience', audienceIncludes(claims.aud, expected.audience), true],
    ['repository_id', claims.repository_id, expected.repositoryId],
    ['workflow', claims.workflow, expected.workflow],
    ['workflow_ref', claims.workflow_ref, expected.workflowRef],
    ['job_workflow_ref', claims.job_workflow_ref, expected.jobWorkflowRef],
    ['environment', claims.environment, expected.environment],
    ['ref', claims.ref, expected.ref],
    ['sha', claims.sha, expected.commitSha],
    ['run_id', claims.run_id, expected.runId],
    ['run_attempt', claims.run_attempt, expected.runAttempt],
  ]
  if (checks.some(([, actual, wanted]) => wanted !== undefined && actual !== wanted && !same(actual, wanted))) {
    throw failure('OIDC_CLAIM_MISMATCH', 'GitHub OIDC claims do not match the release policy')
  }
  if (![claims.iat, claims.exp].every((value) => Number.isFinite(value))) {
    throw failure('OIDC_TIME_INVALID', 'GitHub OIDC token has invalid time claims')
  }
  if (claims.iat > now + skew || claims.exp < now - skew || claims.exp <= claims.iat) {
    throw failure('OIDC_EXPIRED', 'GitHub OIDC token is outside its validity window')
  }
  if (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now + skew)) {
    throw failure('OIDC_NOT_YET_VALID', 'GitHub OIDC token is not yet valid')
  }
  return claims
}

export async function verifyGithubOidc(token, {
  jwks,
  jwksUrl = `${GITHUB_OIDC_ISSUER}/.well-known/jwks`,
  expected = {},
  now = Math.floor(Date.now() / 1000),
  skew = 60,
} = {}) {
  const decoded = decodeJwt(token)
  if (decoded.header.alg !== 'RS256' || typeof decoded.header.kid !== 'string') {
    throw failure('OIDC_ALGORITHM', 'unsupported GitHub OIDC signing algorithm')
  }
  const keySet = jwks || await (async () => {
    const response = await fetch(jwksUrl)
    if (!response.ok) throw failure('OIDC_JWKS', 'unable to load GitHub OIDC keys')
    return response.json()
  })()
  const key = keySet?.keys?.find((candidate) => candidate.kid === decoded.header.kid && candidate.kty === 'RSA')
  if (!key) throw failure('OIDC_KEY', 'GitHub OIDC signing key is not trusted')
  let valid = false
  try {
    valid = verify('RSA-SHA256', Buffer.from(decoded.signingInput), createPublicKey({ key, format: 'jwk' }), decoded.signature)
  } catch {
    throw failure('OIDC_SIGNATURE', 'GitHub OIDC signature is invalid')
  }
  if (!valid) throw failure('OIDC_SIGNATURE', 'GitHub OIDC signature is invalid')
  return validateGithubClaims(decoded.payload, expected, now, skew)
}

function digestValue(value) {
  const digest = typeof value === 'string' && value.startsWith('sha256:') ? value.slice(7) : value
  if (!/^[0-9a-f]{64}$/u.test(digest || '')) throw failure('ATTESTATION_DIGEST', 'artifact attestation has no valid SHA-256 subject')
  return digest
}

export function assertAttestationBinding(attestation, claims, expected = {}) {
  if (!attestation?.verified) throw failure('ATTESTATION_UNVERIFIED', 'artifact attestation was not cryptographically verified')
  if (expected.repository && attestation.repository !== expected.repository) {
    throw failure('ATTESTATION_BINDING_MISMATCH', 'artifact attestation is bound to a different repository')
  }
  if (digestValue(attestation.subjectDigest) !== digestValue(expected.artifactDigest || attestation.subjectDigest)) {
    throw failure('ATTESTATION_DIGEST_MISMATCH', 'artifact attestation subject does not match the release artifact')
  }
  const bindings = [
    ['repository', attestation.repository, expected.repository],
    ['workflow', attestation.workflow, expected.workflow],
    ['commit', attestation.commitSha, claims.sha],
    ['run id', attestation.runId, claims.run_id],
    ['run attempt', attestation.runAttempt, claims.run_attempt],
  ]
  if (bindings.some(([, actual, wanted]) => actual !== undefined && !same(actual, wanted))) {
    throw failure('ATTESTATION_BINDING_MISMATCH', 'artifact attestation is bound to a different workflow run')
  }
  return true
}

export function buildFactFromVerifiedInputs({
  token,
  claims,
  attestation,
  expected = {},
  adapterKeyId,
  adapterPrivateKey,
  adapterPublicKey,
  validForSeconds = null,
}) {
  if (!adapterKeyId) throw failure('ADAPTER_KEY', 'BuildFact adapter key id is required')
  assertAttestationBinding(attestation, claims, expected)
  if (validForSeconds !== null && (!Number.isSafeInteger(validForSeconds) || validForSeconds < 60 || validForSeconds > 604800)) {
    throw failure('BUILD_FACT_TIME_INVALID', 'BuildFact retention must be between 60 seconds and 7 days')
  }
  const issuedAt = Number(claims.iat)
  const fact = {
    version: 1,
    issuerHash: sha256Hex(claims.iss),
    audienceHash: sha256Hex(Array.isArray(claims.aud) ? claims.aud.join('\0') : claims.aud),
    immutableRepositoryId: Number(claims.repository_id),
    workflowRefHash: sha256Hex(claims.workflow_ref),
    jobWorkflowRefHash: claims.job_workflow_ref ? sha256Hex(claims.job_workflow_ref) : null,
    environmentHash: sha256Hex(claims.environment || ''),
    runId: Number(claims.run_id),
    runAttempt: Number(claims.run_attempt),
    commitSha: claims.sha,
    artifactDigest: digestValue(attestation.subjectDigest),
    issuedAt,
    expiresAt: validForSeconds === null ? Number(claims.exp) : issuedAt + validForSeconds,
    originalOidcHash: sha256Hex(token),
    originalAttestationHash: sha256Hex(JSON.stringify(attestation.raw || attestation)),
    adapterKeyId,
  }
  const signedFact = { ...fact, ...(adapterPublicKey ? { adapterPublicKey } : {}) }
  return { ...signedFact, adapterSignature: signBuildFact(signedFact, adapterPrivateKey) }
}

function buildFactMap(fact) {
  return new Map([
    [1, fact.version],
    [2, Buffer.from(fact.issuerHash, 'hex')],
    [3, Buffer.from(fact.audienceHash, 'hex')],
    [4, fact.immutableRepositoryId],
    [5, Buffer.from(fact.workflowRefHash, 'hex')],
    [6, fact.jobWorkflowRefHash ? Buffer.from(fact.jobWorkflowRefHash, 'hex') : null],
    [7, Buffer.from(fact.environmentHash, 'hex')],
    [8, fact.runId],
    [9, fact.runAttempt],
    [10, Buffer.from(fact.commitSha, 'hex')],
    [11, Buffer.from(fact.artifactDigest, 'hex')],
    [12, fact.issuedAt],
    [13, fact.expiresAt],
    [14, Buffer.from(fact.originalOidcHash, 'hex')],
    [15, Buffer.from(fact.originalAttestationHash, 'hex')],
    [16, fact.adapterKeyId],
    [17, fact.adapterPublicKey ? Buffer.from(fact.adapterPublicKey, 'base64') : null],
  ])
}

export function buildFactDigest(fact) {
  return createHash('sha256').update(Buffer.concat([Buffer.from(`${DOMAINS.build}\0`), encodeCanonical(buildFactMap(fact))])).digest()
}

export function signBuildFact(fact, privateKey) {
  if (!privateKey) throw failure('ADAPTER_KEY', 'BuildFact adapter signing key is required')
  return sign(null, buildFactDigest(fact), privateKey).toString('base64')
}

export function verifyBuildFact(fact, publicKey) {
  if (!fact?.adapterSignature || !publicKey) return false
  try {
    return verify(null, buildFactDigest(fact), publicKey, Buffer.from(fact.adapterSignature, 'base64'))
  } catch {
    return false
  }
}

export function validateBuildFact(fact, now = Math.floor(Date.now() / 1000), skew = 60) {
  if (
    fact?.version !== 1 ||
    !Number.isSafeInteger(fact.immutableRepositoryId) ||
    fact.immutableRepositoryId < 1 ||
    !Number.isSafeInteger(fact.runId) ||
    fact.runId < 1 ||
    !Number.isSafeInteger(fact.runAttempt) ||
    fact.runAttempt < 1
  ) {
    throw failure('BUILD_FACT_INVALID', 'BuildFact has invalid identity fields')
  }
  if (!/^[0-9a-f]{40}$/u.test(fact.commitSha || '') || !/^[0-9a-f]{64}$/u.test(fact.artifactDigest || '')) {
    throw failure('BUILD_FACT_INVALID', 'BuildFact has invalid artifact fields')
  }
  if (!Number.isFinite(fact.issuedAt) || !Number.isFinite(fact.expiresAt) || fact.expiresAt <= fact.issuedAt) {
    throw failure('BUILD_FACT_TIME_INVALID', 'BuildFact has invalid time bounds')
  }
  if (fact.issuedAt > now + skew || fact.expiresAt < now - skew) {
    throw failure('BUILD_FACT_EXPIRED', 'BuildFact is outside its validity window')
  }
  return fact
}

export async function verifyArtifactWithGh({
  artifactPath,
  repository,
  signerWorkflow,
  sourceDigest,
  sourceRef,
  certOidcIssuer = GITHUB_OIDC_ISSUER,
  ghPath = 'gh',
}) {
  if (!artifactPath || !repository || !signerWorkflow) {
    throw failure('ATTESTATION_CONFIG', 'artifact path, repository, and signer workflow are required')
  }
  const args = [
    'attestation',
    'verify',
    artifactPath,
    '--repo',
    repository,
    '--format',
    'json',
    '--cert-oidc-issuer',
    certOidcIssuer,
  ]
  if (signerWorkflow) args.push('--signer-workflow', signerWorkflow)
  if (sourceDigest) args.push('--source-digest', sourceDigest)
  if (sourceRef) args.push('--source-ref', sourceRef)
  const { stdout } = await execFileAsync(ghPath, args, { maxBuffer: 4 * 1024 * 1024 })
  let parsed
  try {
    parsed = JSON.parse(stdout)
  } catch {
    throw failure('ATTESTATION_OUTPUT', 'GitHub CLI returned invalid attestation JSON')
  }
  const result = Array.isArray(parsed) ? parsed[0] : parsed
  const statement = result?.verificationResult?.statement
  const subject = statement?.subject?.[0]
  const digest = subject?.digest?.sha256
  if (!digest) throw failure('ATTESTATION_OUTPUT', 'GitHub attestation did not contain a SHA-256 subject')
  return {
    verified: true,
    subjectDigest: `sha256:${digest}`,
    repository,
    signerWorkflow,
    raw: result,
  }
}
