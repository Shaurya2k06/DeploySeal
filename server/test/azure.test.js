import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import { test } from 'node:test'
import { AzureArmProvider, AzureKeyVaultReceiptSigner, AzureTeeAttestation } from '../src/azure.js'

const operationId = 'b'.repeat(64)
const operation = { core: { targetId: 'deployseal-azure-demo', artifactDigest: 'c'.repeat(64) } }

function deployment(status = 'Succeeded') {
  return {
    id: `/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Resources/deployments/${operationId}`,
    name: operationId,
    properties: {
      provisioningState: status,
      timestamp: '2026-09-12T00:00:30.000Z',
      parameters: {
        DeploySealOperationId: { value: operationId },
        DeploySealArtifactDigest: { value: operation.core.artifactDigest },
      },
      outputs: {},
    },
  }
}

test('Azure ARM adapter uses the operation id as the durable deployment name', async () => {
  const calls = []
  const client = {
    async request(url, input) {
      calls.push({ url, input })
      if (input.method === 'PUT') return deployment()
      if (url.includes('/providers/Microsoft.Resources/tags/default?')) {
        return { properties: { tags: { DeploySealOperationId: operationId, DeploySealArtifactDigest: operation.core.artifactDigest } } }
      }
      const notFound = Object.assign(new Error('missing'), { statusCode: 404 })
      throw notFound
    },
  }
  const provider = new AzureArmProvider({ subscriptionId: 'sub', resourceGroup: 'rg', client })
  const accepted = await provider.execute({ operationId, operation })

  assert.equal(calls[1].input.method, 'PUT')
  assert.match(calls[1].url, new RegExp(`/deployments/${operationId}\\?`))
  assert.equal(calls[1].input.body.properties.parameters.DeploySealOperationId.value, operationId)
  assert.equal(accepted.status, 'SUCCEEDED')
  assert.equal(accepted.actualArtifactDigest, operation.core.artifactDigest)
  assert.equal(accepted.actualTarget, operation.core.targetId)
  assert.equal(accepted.actualTargetResourceId, '/subscriptions/sub/resourceGroups/rg')

  const mismatch = { ...deployment(), properties: { ...deployment().properties, parameters: { DeploySealOperationId: { value: operationId }, DeploySealArtifactDigest: { value: 'd'.repeat(64) } } } }
  assert.throws(
    () => provider.execution(mismatch, operationId, operation),
    /Azure deployment parameters do not match/u,
  )
})

test('Azure Key Vault signer signs and verifies receipt digests without exporting a key', async () => {
  const calls = []
  const signature = Buffer.from([1, 2, 3])
  const client = {
    async request(url, input) {
      calls.push({ url, input })
      if (input.method === 'POST' && url.includes('/sign?')) return { kid: 'https://vault.vault.azure.net/keys/deployseal/v1', value: signature.toString('base64url') }
      if (input.method === 'POST' && url.includes('/verify?')) return { value: true }
      return { key: { kid: 'https://vault.vault.azure.net/keys/deployseal/v1' } }
    },
  }
  const signer = new AzureKeyVaultReceiptSigner({ vaultUrl: 'https://vault.vault.azure.net', keyName: 'deployseal', client })
  const message = Buffer.from('receipt')
  assert.deepEqual(await signer.sign(message), signature)
  assert.equal(await signer.verify(message, signature), true)
  assert.equal(calls[1].input.body.alg, 'PS256')
  assert.equal(calls[1].input.body.value, message.toString('base64url'))
  assert.equal(calls[2].input.body.digest, message.toString('base64url'))
  assert.equal(calls[2].input.body.value, signature.toString('base64url'))
})

test('Azure TEE attestation requires a signed, non-debuggable SEV-SNP token', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const header = { alg: 'RS256', kid: 'test-key', jku: 'https://provider.attest.azure.net/certs' }
  const payload = {
    iss: 'https://provider.attest.azure.net',
    iat: Math.floor(Date.now() / 1000) - 1,
    exp: Math.floor(Date.now() / 1000) + 300,
    'x-ms-attestation-type': 'sevsnpvm',
    'x-ms-compliance-status': 'azure-compliant-cvm',
    'x-ms-sevsnpvm-is-debuggable': false,
    'x-ms-sevsnpvm-launchmeasurement': 'ab12',
  }
  const encoded = (value) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const signingInput = `${encoded(header)}.${encoded(payload)}`
  const token = `${signingInput}.${sign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url')}`
  const previousToken = process.env.DEPLOYSEAL_AZURE_ATTESTATION_TOKEN
  const previousEndpoint = process.env.DEPLOYSEAL_AZURE_ATTESTATION_ENDPOINT
  const previousMeasurements = process.env.DEPLOYSEAL_AZURE_ALLOWED_MEASUREMENTS
  process.env.DEPLOYSEAL_AZURE_ATTESTATION_TOKEN = token
  process.env.DEPLOYSEAL_AZURE_ATTESTATION_ENDPOINT = 'https://provider.attest.azure.net/attest/SevSnpVm'
  process.env.DEPLOYSEAL_AZURE_ALLOWED_MEASUREMENTS = 'ab12'
  try {
    const attestation = await AzureTeeAttestation.fromEnv({
      fetchImpl: async () => ({ ok: true, async json() { return { keys: [{ kid: 'test-key', ...publicKey.export({ format: 'jwk' }) }] } } }),
    })
    assert.equal(attestation.measurement, 'ab12')
  } finally {
    if (previousToken === undefined) delete process.env.DEPLOYSEAL_AZURE_ATTESTATION_TOKEN
    else process.env.DEPLOYSEAL_AZURE_ATTESTATION_TOKEN = previousToken
    if (previousEndpoint === undefined) delete process.env.DEPLOYSEAL_AZURE_ATTESTATION_ENDPOINT
    else process.env.DEPLOYSEAL_AZURE_ATTESTATION_ENDPOINT = previousEndpoint
    if (previousMeasurements === undefined) delete process.env.DEPLOYSEAL_AZURE_ALLOWED_MEASUREMENTS
    else process.env.DEPLOYSEAL_AZURE_ALLOWED_MEASUREMENTS = previousMeasurements
  }
})
