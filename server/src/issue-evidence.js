import { createPrivateKey, createPublicKey } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { signEvidenceFact, validateEvidenceFact } from './evidence.js'
import { sha256Hex } from './protocol.js'

function parseArguments(values) {
  const result = {}
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index]?.slice(2)
    if (!values[index]?.startsWith('--') || !values[index + 1] || Object.hasOwn(result, name)) {
      throw new Error('arguments must be unique --name value pairs')
    }
    result[name] = values[index + 1]
  }
  return result
}

function required(options, name) {
  if (!options[name]) throw new Error(`--${name} is required`)
  return options[name]
}

function jsonFile(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch (cause) {
    throw new Error(`${label} must contain valid JSON`, { cause })
  }
}

function digestFile(path, label) {
  try {
    return sha256Hex(readFileSync(path))
  } catch (cause) {
    throw new Error(`${label} could not be read`, { cause })
  }
}

function integer(value, name) {
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed)) throw new Error(`--${name} must be an integer`)
  return parsed
}

export function issueEvidenceFact(options, now = Math.floor(Date.now() / 1000)) {
  const scope = options['scope-file']
    ? jsonFile(options['scope-file'], '--scope-file')
    : {
        commitSha: required(options, 'commit-sha'),
        providerId: required(options, 'provider-id'),
        targetId: required(options, 'target-id'),
        region: required(options, 'region'),
        policyEpoch: integer(required(options, 'policy-epoch'), 'policy-epoch'),
      }
  const issuedAt = options['issued-at'] ? integer(options['issued-at'], 'issued-at') : now
  const expiresAt = options['expires-at']
    ? integer(options['expires-at'], 'expires-at')
    : issuedAt + integer(options['valid-for-seconds'] ?? 3600, 'valid-for-seconds')
  const privateKey = createPrivateKey(readFileSync(required(options, 'private-key-file')))
  const fact = signEvidenceFact({
    version: 1,
    kind: required(options, 'kind'),
    role: required(options, 'role'),
    schemaId: required(options, 'schema-id'),
    schemaVersion: integer(required(options, 'schema-version'), 'schema-version'),
    subjectArtifactDigest: required(options, 'subject-artifact-digest'),
    operationScope: scope,
    issuedAt,
    expiresAt,
    payloadCommitment: options['payload-commitment'] || digestFile(required(options, 'payload-file'), '--payload-file'),
    evidenceCiphertextHash: options['evidence-ciphertext-hash'] || digestFile(required(options, 'ciphertext-file'), '--ciphertext-file'),
    signerKeyId: required(options, 'signer-key-id'),
  }, privateKey)
  validateEvidenceFact(fact, {}, now)
  return { fact, publicKey: createPublicKey(privateKey) }
}

export function run(argv = process.argv.slice(2)) {
  const options = parseArguments(argv)
  const { fact, publicKey } = issueEvidenceFact(options)
  const output = options.output || 'evidence-fact.json'
  writeFileSync(output, `${JSON.stringify(fact, null, 2)}\n`, { mode: 0o600 })
  if (options['public-key-output']) {
    writeFileSync(options['public-key-output'], publicKey.export({ format: 'pem', type: 'spki' }), { mode: 0o644 })
  }
  console.log(JSON.stringify({ output, kind: fact.kind, signerKeyId: fact.signerKeyId }))
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  try {
    run()
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
