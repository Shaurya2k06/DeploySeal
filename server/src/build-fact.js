import { createHash, createPublicKey } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { buildFactFromVerifiedInputs, verifyArtifactWithGh, verifyGithubOidc } from './github.js'

function argumentsMap(values) {
  const result = {}
  for (let index = 0; index < values.length; index += 2) {
    if (!values[index]?.startsWith('--') || !values[index + 1]) throw new Error('arguments must be --name value pairs')
    result[values[index].slice(2)] = values[index + 1]
  }
  return result
}

function required(options, name) {
  const value = options[name]
  if (!value) throw new Error(`--${name} is required`)
  return value
}

const options = argumentsMap(process.argv.slice(2))
const artifactPath = required(options, 'artifact')
const repository = required(options, 'repository')
const signerWorkflow = required(options, 'signer-workflow')
const token = readFileSync(required(options, 'oidc-token-file'), 'utf8').trim()
const privateKey = readFileSync(required(options, 'private-key-file'), 'utf8')
const adapterPublicKey = options['public-key-file']
  ? createPublicKey(readFileSync(options['public-key-file'])).export({ format: 'der', type: 'spki' }).toString('base64')
  : undefined
const artifactDigest = createHash('sha256').update(readFileSync(artifactPath)).digest('hex')
const expected = {
  audience: required(options, 'audience'),
  repositoryId: Number(required(options, 'repository-id')),
  workflow: required(options, 'workflow'),
  workflowRef: options['workflow-ref'] || process.env.GITHUB_WORKFLOW_REF,
  environment: options.environment || process.env.DEPLOYSEAL_EXPECTED_ENVIRONMENT,
  commitSha: options.sha || process.env.GITHUB_SHA,
  runId: options['run-id'] || process.env.GITHUB_RUN_ID,
  runAttempt: options['run-attempt'] || process.env.GITHUB_RUN_ATTEMPT || '1',
  ref: options.ref || process.env.GITHUB_REF,
}
const claims = await verifyGithubOidc(token, { expected })
const attestation = await verifyArtifactWithGh({
  artifactPath,
  repository,
  signerWorkflow,
  sourceDigest: claims.sha,
  sourceRef: claims.ref,
})
const fact = buildFactFromVerifiedInputs({
  token,
  claims,
  attestation,
  expected: { artifactDigest, repository },
  adapterKeyId: required(options, 'adapter-key-id'),
  adapterPrivateKey: privateKey,
  adapterPublicKey,
})
const outputPath = options.output || 'build-fact.json'
writeFileSync(outputPath, `${JSON.stringify(fact, null, 2)}\n`, { mode: 0o600 })
console.log(JSON.stringify({ output: outputPath, artifactDigest, runId: fact.runId, runAttempt: fact.runAttempt }))
