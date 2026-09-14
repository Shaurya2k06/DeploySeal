import { createServer } from 'node:http'
import { createPublicKey } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { AwsCloudFormationProvider, AwsKmsReceiptSigner } from './aws.js'
import { AzureArmProvider, AzureKeyVaultReceiptSigner, AzureTeeAttestation } from './azure.js'
import { DeploySealBroker } from './broker.js'
import { finalizeLocalCompactReceipt, verifyLocalCompactProof } from './compact.js'
import { configuredEvidenceFacts, evidenceFromFacts, verifyEvidenceBundle } from './evidence.js'
import { validateBuildFact, verifyBuildFact } from './github.js'
import { DEMO_EVIDENCE, PRIVATE_POLICY } from './protocol.js'

const port = Number(process.env.PORT || 8787)
const host = process.env.HOST || '127.0.0.1'
const useAws = process.env.DEPLOYSEAL_PROVIDER === 'aws-cloudformation'
const useAzure = process.env.DEPLOYSEAL_PROVIDER === 'azure-arm'
const useExternalProvider = useAws || useAzure
const useMidnight = useExternalProvider && Boolean(process.env.DEPLOYSEAL_MIDNIGHT_CONTRACT_ADDRESS && process.env.DEPLOYSEAL_MIDNIGHT_SEED_HEX)
let midnightClientPromise

async function midnightClient() {
  midnightClientPromise ||= import('@deployseal/deployseal-contract/preprod').then(({ createMidnightClient }) => createMidnightClient())
  return midnightClientPromise
}

function configuredJson(name, fallback) {
  const value = process.env[name]
  if (!value) return fallback
  try {
    return JSON.parse(value)
  } catch {
    throw Object.assign(new Error(`${name} must contain valid JSON`), { code: 'INVALID_CONFIG' })
  }
}

function configuredBuildFact() {
  const raw = process.env.DEPLOYSEAL_BUILD_FACT_JSON
  const path = process.env.DEPLOYSEAL_BUILD_FACT_FILE
  if (!raw && !path) return null
  let fact
  try {
    fact = JSON.parse(raw || readFileSync(path, 'utf8'))
  } catch {
    throw Object.assign(new Error('DEPLOYSEAL_BUILD_FACT_JSON/FILE must contain valid JSON'), { code: 'INVALID_CONFIG' })
  }
  const keyValue = process.env.DEPLOYSEAL_BUILD_ADAPTER_PUBLIC_KEY
  const keyPath = process.env.DEPLOYSEAL_BUILD_ADAPTER_PUBLIC_KEY_FILE
  if (!keyValue && !keyPath) throw Object.assign(new Error('BuildFact verification key is required'), { code: 'INVALID_CONFIG' })
  let publicKey
  try {
    publicKey = createPublicKey(keyValue || readFileSync(keyPath))
  } catch {
    throw Object.assign(new Error('BuildFact verification key is invalid'), { code: 'INVALID_CONFIG' })
  }
  try {
    validateBuildFact(fact)
  } catch {
    throw Object.assign(new Error('BuildFact is expired or invalid'), { code: 'INVALID_CONFIG' })
  }
  if (!verifyBuildFact(fact, publicKey)) throw Object.assign(new Error('BuildFact signature is invalid'), { code: 'INVALID_CONFIG' })
  if (fact.adapterPublicKey) {
    const expected = publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
    if (fact.adapterPublicKey !== expected) throw Object.assign(new Error('BuildFact key binding is invalid'), { code: 'INVALID_CONFIG' })
  }
  return fact
}

const provider = useAws ? new AwsCloudFormationProvider() : useAzure ? new AzureArmProvider() : null
const receiptSigner = useAws ? new AwsKmsReceiptSigner() : useAzure ? new AzureKeyVaultReceiptSigner() : null
const azureAttestation = useAzure ? await AzureTeeAttestation.fromEnv() : null
if (azureAttestation) process.env.DEPLOYSEAL_ENCLAVE_MEASUREMENT = azureAttestation.measurement
const azureTarget = process.env.DEPLOYSEAL_AZURE_TARGET || 'deployseal-azure-demo'
const azureLocation = process.env.DEPLOYSEAL_AZURE_LOCATION || 'eastus'
const policy = configuredJson(
  'DEPLOYSEAL_POLICY_JSON',
  useAzure ? { ...PRIVATE_POLICY, allowedProviderId: 'azure-arm', allowedTargetId: azureTarget, allowedRegion: azureLocation } : PRIVATE_POLICY,
)
const buildFact = configuredBuildFact()
if (useAzure && process.env.DEPLOYSEAL_REQUIRE_BUILD_FACT !== 'false' && !buildFact) {
  throw Object.assign(new Error('a signed BuildFact is required for Azure provider mode'), { code: 'INVALID_CONFIG' })
}
const baseEvidence = {
  ...configuredJson(
    'DEPLOYSEAL_EVIDENCE_JSON',
    useAzure ? { ...DEMO_EVIDENCE, providerId: 'azure-arm', targetId: azureTarget, region: azureLocation } : DEMO_EVIDENCE,
  ),
  ...(buildFact
    ? {
        repositoryId: buildFact.immutableRepositoryId,
        runId: buildFact.runId,
        runAttempt: buildFact.runAttempt,
        commitSha: buildFact.commitSha,
        artifactDigest: buildFact.artifactDigest,
      }
    : {}),
}
const configuredFacts = configuredEvidenceFacts()
if (useAzure && process.env.DEPLOYSEAL_REQUIRE_EVIDENCE_FACTS === 'true' && !configuredFacts) {
  throw Object.assign(new Error('signed EvidenceFacts are required for Azure provider mode'), { code: 'INVALID_CONFIG' })
}
const evidence = configuredFacts
  ? {
      ...baseEvidence,
      ...evidenceFromFacts(
        verifyEvidenceBundle(configuredFacts.bundle, configuredFacts.publicKeys, {
          artifactDigest: baseEvidence.artifactDigest,
          commitSha: baseEvidence.commitSha,
          providerId: baseEvidence.providerId,
          targetId: baseEvidence.targetId,
          region: baseEvidence.region,
          policyEpoch: policy.epoch,
        }),
      ),
    }
  : baseEvidence
const proofVerifier = useMidnight
  ? async ({ core, policyRoot }) => (await midnightClient()).reserve(core, policyRoot)
  : useAws
    ? null
    : verifyLocalCompactProof
const finalizeVerifier = useMidnight
  ? async ({ core, receiptHash, policyRoot }) => (await midnightClient()).finalize(core, receiptHash, policyRoot)
  : useAws
    ? null
    : finalizeLocalCompactReceipt
const attestationCheck = azureAttestation
  ? ({ operationDigest }) => process.env.DEPLOYSEAL_REQUIRE_OPERATION_ATTESTATION === 'true'
    ? azureAttestation.attestChallenge(operationDigest.toString('hex'))
    : azureAttestation.refresh()
  : null
const broker = new DeploySealBroker({ provider, receiptSigner, proofVerifier, finalizeVerifier, policy, evidence, buildFact, attestationCheck })

function headers() {
  return {
    'access-control-allow-origin': process.env.CLIENT_ORIGIN || 'http://127.0.0.1:5173',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'content-type',
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
  }
}

function send(response, status, body) {
  response.writeHead(status, headers())
  response.end(JSON.stringify(body))
}

async function readJson(request) {
  const chunks = []
  let size = 0
  for await (const chunk of request) {
    size += chunk.length
    if (size > 1024 * 1024) throw Object.assign(new Error('request too large'), { statusCode: 413 })
    chunks.push(chunk)
  }
  if (!chunks.length) return {}
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    throw Object.assign(new Error('invalid JSON'), { statusCode: 400 })
  }
}

function validScenario(value) {
  return ['crash', 'happy', 'invalid'].includes(value) ? value : 'crash'
}

const server = createServer(async (request, response) => {
  if (request.method === 'OPTIONS') {
    response.writeHead(204, headers())
    response.end()
    return
  }

  const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`)

  try {
    if (request.method === 'GET' && url.pathname === '/api/health') {
      send(response, 200, { ok: true, mode: broker.snapshot().mode })
      return
    }

    if (request.method === 'GET' && url.pathname === '/api/release') {
      send(response, 200, broker.snapshot())
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/release/start') {
      const body = await readJson(request)
      let resolveAccepted
      const accepted = new Promise((resolve) => {
        resolveAccepted = resolve
      })
      const running = broker.start({
        scenario: validScenario(body?.scenario),
        onAccepted: (snapshot) => resolveAccepted({ accepted: true, pending: true, code: 'OPERATION_ACCEPTED', snapshot }),
      })
      const result = await Promise.race([running, accepted])
      if (result.pending) {
        running.catch((error) => console.error('background release failed', error))
        send(response, 202, result)
        return
      }
      send(response, result.accepted || result.code === 'OPERATION_EXISTS' ? 200 : 422, result)
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/release/recover') {
      let resolveAccepted
      const accepted = new Promise((resolve) => {
        resolveAccepted = resolve
      })
      const running = broker.recover({
        onAccepted: (snapshot) => resolveAccepted({ accepted: true, pending: true, code: 'RECOVERY_ACCEPTED', snapshot }),
      })
      const result = await Promise.race([running, accepted])
      if (result.pending) {
        running.catch((error) => console.error('background recovery failed', error))
        send(response, 202, result)
        return
      }
      send(response, result.accepted ? 200 : 409, result)
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/release/replay') {
      const result = await broker.replay()
      send(response, 409, result)
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/audit/disclose') {
      const body = await readJson(request)
      const fields = Array.isArray(body?.fields) ? body.fields.slice(0, 8) : []
      const result = await broker.disclose(fields, { purpose: body?.purpose, recipientId: body?.recipientId })
      send(response, result.accepted ? 200 : 409, result)
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/audit/verify') {
      const result = await broker.verifyDisclosure(await readJson(request))
      send(response, 200, result)
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/receipt/verify') {
      send(response, 200, await broker.verifyReceipt())
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/receipt/export') {
      const result = await broker.receiptBundle()
      send(response, result.accepted ? 200 : 409, result)
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/reset') {
      const result = await broker.reset()
      send(response, result.accepted === false ? 409 : 200, result.accepted === false ? result : { accepted: true, snapshot: result })
      return
    }

    send(response, 404, { error: { code: 'NOT_FOUND', message: 'Not found' } })
  } catch (error) {
    const status = Number.isInteger(error.statusCode) ? error.statusCode : 500
    send(response, status, { error: { code: 'INTERNAL_ERROR', message: status === 500 ? 'Request failed' : error.message } })
  }
})

if (process.argv[1] === new URL(import.meta.url).pathname) {
  server.listen(port, host, () => {
    console.log(`DeploySeal broker listening on http://${host}:${port}`)
  })
}

server.on('close', () => {
  void midnightClientPromise?.then((client) => client.close())
})

export { server, broker }
