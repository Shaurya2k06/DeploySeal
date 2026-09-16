import { createCipheriv, createHash, createPublicKey, randomBytes, verify } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { evidenceFactDigest, verifyEvidenceBundle } from '../../server/src/evidence.js'
import { validateBuildFact } from '../../server/src/github.js'

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const secretDirectory = process.env.DEPLOYSEAL_AZURE_SECRET_DIR || '/etc/deployseal/secrets'
const registryPath = process.env.DEPLOYSEAL_PRODUCTION_ISSUER_REGISTRY_FILE || `${secretDirectory}/production-issuer-registry-json`

function az(args) {
  return execFileSync('az', [...args, '--only-show-errors'], { encoding: 'utf8' }).trim()
}

function json(value, label) {
  try {
    return JSON.parse(value)
  } catch (cause) {
    throw new Error(`${label} was not valid JSON`, { cause })
  }
}

function secret(name) {
  return readFileSync(resolve(secretDirectory, name), 'utf8').trim()
}

function hash(value) {
  return createHash('sha256').update(value).digest('hex')
}

function encrypted(payload) {
  const key = randomBytes(32)
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()])
  return Buffer.from(JSON.stringify({
    algorithm: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  }))
}

function check(command, args, cwd = repo) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' })
  const output = `${result.stdout || ''}${result.stderr || ''}`
  return { command: [command, ...args].join(' '), status: result.status ?? 1, outputHash: hash(output) }
}

function publicKeyPem(jwk) {
  const publicJwk = Object.fromEntries(Object.entries(jwk).filter(([, value]) => value !== null))
  return createPublicKey({ key: publicJwk, format: 'jwk' }).export({ format: 'pem', type: 'spki' }).toString()
}

function signWithIssuer(issuer, digest) {
  az(['login', '--identity', '--client-id', issuer.identity.clientId, '--allow-no-subscriptions'])
  const response = json(az([
    'keyvault', 'key', 'sign', '--vault-name', issuer.keyVault.name, '--name', issuer.keyVault.keyName,
    '--algorithm', 'RS256', '--digest', createHash('sha256').update(digest).digest('base64'), '--output', 'json',
  ]), `signature ${issuer.keyId}`)
  const key = json(az([
    'keyvault', 'key', 'show', '--vault-name', issuer.keyVault.name, '--name', issuer.keyVault.keyName,
    '--query', 'key', '--output', 'json',
  ]), `public key ${issuer.keyId}`)
  const publicJwk = Object.fromEntries(Object.entries(key).filter(([, value]) => value !== null))
  const publicKey = createPublicKey({ key: publicJwk, format: 'jwk' })
  const signature = Buffer.from(response.signature, 'base64')
  if (!verify(null, digest, publicKey, signature)) throw new Error(`signature verification failed for ${issuer.keyId}`)
  return { signature: signature.toString('base64'), publicKey: publicKeyPem(key) }
}

function fact({ issuer, payload, scope, subjectArtifactDigest }) {
  const payloadBytes = Buffer.from(`${JSON.stringify(payload, null, 2)}\n`)
  const ciphertextBytes = encrypted(payloadBytes)
  const unsigned = {
    version: 1,
    kind: issuer.kind,
    role: issuer.role,
    schemaId: `deployseal/${issuer.kind}`,
    schemaVersion: 1,
    subjectArtifactDigest,
    operationScope: scope,
    issuedAt: Math.floor(Date.now() / 1000),
    expiresAt: Math.floor(Date.now() / 1000) + 86_400,
    payloadCommitment: hash(payloadBytes),
    evidenceCiphertextHash: hash(ciphertextBytes),
    signerKeyId: issuer.keyId,
  }
  const digest = evidenceFactDigest(unsigned)
  const signed = signWithIssuer(issuer, digest)
  return { fact: { ...unsigned, signature: signed.signature }, publicKey: signed.publicKey }
}

function sbom() {
  return ['server', 'contracts/deployseal', 'client'].map((directory) => {
    const lockfile = json(readFileSync(resolve(repo, directory, 'package-lock.json'), 'utf8'), `lockfile ${directory}`)
    const components = Object.entries(lockfile.packages || {})
      .filter(([path]) => path.includes('node_modules/'))
      .map(([path, packageInfo]) => ({
        type: 'library',
        name: packageInfo.name || path.split('node_modules/').at(-1),
        version: packageInfo.version,
      }))
      .filter(({ version }) => typeof version === 'string')
    return {
      directory,
      document: { bomFormat: 'CycloneDX', specVersion: '1.5', version: 1, metadata: { component: { type: 'application', name: lockfile.name } }, components },
      audit: json(spawnSync('npm', ['audit', '--json'], { cwd: resolve(repo, directory), encoding: 'utf8' }).stdout, `audit ${directory}`),
    }
  })
}

function main() {
  const registry = json(readFileSync(registryPath, 'utf8'), 'production issuer registry')
  if (registry.issuerClass !== 'production' || !Array.isArray(registry.issuers) || registry.issuers.length !== 5) {
    throw new Error('production issuer registry must contain five issuers')
  }
  az(['login', '--identity', '--allow-no-subscriptions'])
  const buildFact = json(secret('build-fact-json'), 'BuildFact')
  validateBuildFact(buildFact)
  const policy = json(secret('server-policy-json'), 'server policy')
  const scope = {
    commitSha: buildFact.commitSha,
    providerId: policy.allowedProviderId,
    targetId: policy.allowedTargetId,
    region: policy.allowedRegion,
    policyEpoch: policy.epoch,
  }
  const target = json(az(['group', 'show', '--name', process.env.DEPLOYSEAL_AZURE_RESOURCE_GROUP || 'deployseal-target-rg', '--output', 'json']), 'Azure target')
  const checks = [
    check('npm', ['test'], resolve(repo, 'server')),
    check('npm', ['test'], resolve(repo, 'contracts/deployseal')),
    check('npm', ['run', 'lint'], resolve(repo, 'client')),
    check('npm', ['run', 'build'], resolve(repo, 'client')),
  ]
  if (checks.some(({ status }) => status !== 0)) throw new Error('release evaluation checks failed')
  const issuer = (kind, role) => registry.issuers.find((candidate) => candidate.kind === kind && candidate.role === role) || (() => { throw new Error(`missing production issuer for ${kind}/${role}`) })()
  const facts = [
    fact({
      issuer: issuer('sbom', 'supply-chain'),
      payload: { issuerClass: 'production', source: 'azure-issuer-workload', commitSha: buildFact.commitSha, packages: sbom() },
      scope, subjectArtifactDigest: buildFact.artifactDigest,
    }),
    fact({
      issuer: issuer('model-eval', 'release-validation'),
      payload: { issuerClass: 'production', evaluator: 'DeploySeal release checks', commitSha: buildFact.commitSha, checks },
      scope, subjectArtifactDigest: buildFact.artifactDigest,
    }),
    fact({
      issuer: issuer('residency', 'azure-residency'),
      payload: { issuerClass: 'production', provider: 'azure', resourceGroup: target.name, location: target.location, provisioningState: target.properties?.provisioningState },
      scope, subjectArtifactDigest: buildFact.artifactDigest,
    }),
    fact({
      issuer: issuer('approval', 'security'),
      payload: { issuerClass: 'production', source: 'security-issuer-workload', decision: 'approved', basis: 'attested-build-and-release-checks', commitSha: buildFact.commitSha },
      scope, subjectArtifactDigest: buildFact.artifactDigest,
    }),
    fact({
      issuer: issuer('approval', 'governance'),
      payload: { issuerClass: 'production', source: 'governance-issuer-workload', decision: 'approved', basis: 'immutable-build-fact-and-azure-scope', commitSha: buildFact.commitSha },
      scope, subjectArtifactDigest: buildFact.artifactDigest,
    }),
  ]
  az(['login', '--identity', '--allow-no-subscriptions'])
  const bundle = { version: 1, facts: facts.map(({ fact: value }) => value) }
  const publicKeys = Object.fromEntries(facts.map(({ fact: value, publicKey }) => [value.signerKeyId, publicKey]))
  verifyEvidenceBundle(bundle, Object.fromEntries(Object.entries(publicKeys).map(([id, pem]) => [id, createPublicKey(pem)])), {
    artifactDigest: buildFact.artifactDigest,
    ...scope,
  })
  console.log(`PRODUCTION_BUNDLE_BASE64=${Buffer.from(JSON.stringify(bundle)).toString('base64')}`)
  console.log(`PRODUCTION_KEYS_BASE64=${Buffer.from(JSON.stringify(publicKeys)).toString('base64')}`)
  console.log(JSON.stringify({
    issuerClass: registry.issuerClass,
    scope,
    facts: facts.map(({ fact: value }) => ({ kind: value.kind, role: value.role, signerKeyId: value.signerKeyId })),
  }, null, 2))
}

try {
  main()
} catch (error) {
  console.error(error.message)
  process.exitCode = 1
}
