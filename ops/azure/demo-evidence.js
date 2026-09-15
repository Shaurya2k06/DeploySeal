import { createCipheriv, createHash, createPublicKey, randomBytes, verify } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { evidenceFactDigest, verifyEvidenceBundle } from '../../server/src/evidence.js'
import { validateBuildFact } from '../../server/src/github.js'

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const vault = process.env.AZURE_KEY_VAULT_NAME || 'deploysealkv260912'
const issuerKeys = {
  sbom: 'deployseal-evidence-sbom-v1',
  'model-eval': 'deployseal-evidence-model-v1',
  residency: 'deployseal-evidence-residency-v1',
  security: 'deployseal-evidence-security-v1',
  governance: 'deployseal-evidence-governance-v1',
}

function run(command, args, cwd = repo) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' })
  if (result.status !== 0) throw new Error(`${command} ${args.join(' ')} failed: ${result.stderr || result.stdout}`)
  return result.stdout.trim()
}

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
  return az(['keyvault', 'secret', 'show', '--vault-name', vault, '--name', name, '--query', 'value', '--output', 'tsv'])
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

function keyData(name) {
  return json(az(['keyvault', 'key', 'show', '--vault-name', vault, '--name', name, '--query', 'key', '--output', 'json']), `key ${name}`)
}

function signWithKey(name, digest) {
  const keyVaultDigest = createHash('sha256').update(digest).digest()
  const response = json(az([
    'keyvault', 'key', 'sign', '--vault-name', vault, '--name', name,
    '--algorithm', 'RS256', '--digest', keyVaultDigest.toString('base64'), '--output', 'json',
  ]), `signature ${name}`)
  if (typeof response.signature !== 'string' || !response.signature) throw new Error(`Azure Key Vault returned no signature for ${name}`)
  return Buffer.from(response.signature, 'base64')
}

function publicKeyPem(jwk) {
  return createPublicKey({ key: jwk, format: 'jwk' }).export({ format: 'pem', type: 'spki' }).toString()
}

function fact({ kind, role, signerKeyId, payload, scope, subjectArtifactDigest }) {
  const payloadBytes = Buffer.from(`${JSON.stringify(payload, null, 2)}\n`)
  const ciphertextBytes = encrypted(payloadBytes)
  const unsigned = {
    version: 1,
    kind,
    role,
    schemaId: `deployseal/${kind}`,
    schemaVersion: 1,
    subjectArtifactDigest,
    operationScope: scope,
    issuedAt: Math.floor(Date.now() / 1000),
    expiresAt: Math.floor(Date.now() / 1000) + 86_400,
    payloadCommitment: hash(payloadBytes),
    evidenceCiphertextHash: hash(ciphertextBytes),
    signerKeyId,
  }
  const digest = evidenceFactDigest(unsigned)
  const signature = signWithKey(signerKeyId, digest)
  const publicKey = createPublicKey({ key: keyData(signerKeyId), format: 'jwk' })
  if (!verify(null, digest, publicKey, signature)) throw new Error(`signature verification failed for ${signerKeyId}`)
  return { ...unsigned, signature: signature.toString('base64') }
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
      audit: json(run('npm', ['audit', '--json'], resolve(repo, directory)), `audit ${directory}`),
    }
  })
}

function publish(name, value, directory) {
  const path = join(directory, name)
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 })
  az(['keyvault', 'secret', 'set', '--vault-name', vault, '--name', name.replace(/\.json$/u, ''), '--file', path])
}

function main() {
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
  const subjectArtifactDigest = buildFact.artifactDigest
  const checks = [
    check('npm', ['test'], resolve(repo, 'server')),
    check('npm', ['test'], resolve(repo, 'contracts/deployseal')),
    check('npm', ['run', 'lint'], resolve(repo, 'client')),
    check('npm', ['run', 'build'], resolve(repo, 'client')),
  ]
  if (checks.some(({ status }) => status !== 0)) throw new Error('release evaluation checks failed')
  const target = json(az(['group', 'show', '--name', process.env.DEPLOYSEAL_AZURE_RESOURCE_GROUP || 'deployseal-target-rg', '--output', 'json']), 'Azure target')
  const azurePrincipal = json(az(['account', 'show', '--output', 'json']), 'Azure account').user?.name || 'azure-operator'
  const githubPrincipal = run('gh', ['api', 'user', '--jq', '.login'])
  const facts = [
    fact({
      kind: 'sbom', role: 'supply-chain', signerKeyId: issuerKeys.sbom,
      payload: { source: 'npm', commitSha: buildFact.commitSha, packages: sbom() }, scope, subjectArtifactDigest,
    }),
    fact({
      kind: 'model-eval', role: 'release-validation', signerKeyId: issuerKeys['model-eval'],
      payload: { evaluator: 'DeploySeal release checks', commitSha: buildFact.commitSha, checks }, scope, subjectArtifactDigest,
    }),
    fact({
      kind: 'residency', role: 'azure-residency', signerKeyId: issuerKeys.residency,
      payload: { provider: 'azure', resourceGroup: target.name, location: target.location, provisioningState: target.properties?.provisioningState }, scope, subjectArtifactDigest,
    }),
    fact({
      kind: 'approval', role: 'security', signerKeyId: issuerKeys.security,
      payload: { issuerClass: 'operator-demo', source: 'azure-session', principal: azurePrincipal, decision: 'approved', commitSha: buildFact.commitSha }, scope, subjectArtifactDigest,
    }),
    fact({
      kind: 'approval', role: 'governance', signerKeyId: issuerKeys.governance,
      payload: { issuerClass: 'operator-demo', source: 'github-session', principal: githubPrincipal, decision: 'approved', commitSha: buildFact.commitSha }, scope, subjectArtifactDigest,
    }),
  ]
  const bundle = { version: 1, facts }
  const publicKeys = Object.fromEntries(Object.values(issuerKeys).map((name) => [name, publicKeyPem(keyData(name))]))
  verifyEvidenceBundle(bundle, Object.fromEntries(Object.entries(publicKeys).map(([id, pem]) => [id, createPublicKey(pem)])), {
    artifactDigest: subjectArtifactDigest,
    ...scope,
  })
  const directory = mkdtempSync(join(tmpdir(), 'deployseal-evidence-'))
  try {
    publish('evidence-facts-json', bundle, directory)
    publish('evidence-adapter-public-key', publicKeys, directory)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
  console.log(JSON.stringify({ vault, scope, facts: facts.map(({ kind, role, signerKeyId }) => ({ kind, role, signerKeyId })) }, null, 2))
}

try {
  main()
} catch (error) {
  console.error(error.message)
  process.exitCode = 1
}
