import { createHash, createPublicKey, createVerify } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { DefaultAzureCredential } from '@azure/identity'

const ARM_SCOPE = 'https://management.azure.com/.default'
const KEY_VAULT_SCOPE = 'https://vault.azure.net/.default'
const ARM_API_VERSION = '2022-09-01'
const KEY_VAULT_API_VERSION = '7.4'
const OPERATION_ID = /^[0-9a-f]{64}$/u
const DEBUGGABLE_CLAIM = 'x-ms-sevsnpvm-is-debuggable'
const MEASUREMENT_CLAIM = 'x-ms-sevsnpvm-launchmeasurement'

export const AZURE_ARM_CAPABILITIES = Object.freeze({
  nativeIdempotency: true,
  durableQueryByOperationId: true,
  receiptCanBindActualTargetAndDigest: true,
})

function error(code, message, cause = undefined) {
  return Object.assign(new Error(message, cause ? { cause } : undefined), { code })
}

function asIso(value, now) {
  return value ? new Date(value).toISOString() : new Date(now()).toISOString()
}

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex')
}

function encodeBase64Url(value) {
  return Buffer.from(value).toString('base64url')
}

function decodeBase64Url(value) {
  return Buffer.from(value, 'base64url')
}

function jsonFrom(value, label) {
  try {
    return JSON.parse(value)
  } catch (cause) {
    throw error('INVALID_ATTESTATION_TOKEN', `${label} is not valid JSON`, cause)
  }
}

function provisioningStatus(value) {
  switch (String(value || '').toLowerCase()) {
    case 'succeeded':
      return 'SUCCEEDED'
    case 'failed':
    case 'canceled':
    case 'deleted':
      return 'FAILED'
    default:
      return 'PENDING'
  }
}

export class AzureRestClient {
  constructor({ credential = new DefaultAzureCredential(), fetchImpl = globalThis.fetch } = {}) {
    if (typeof fetchImpl !== 'function') throw error('AZURE_HTTP_CONFIG', 'global fetch is required')
    this.credential = credential
    this.fetchImpl = fetchImpl
  }

  async request(url, { scope, method = 'GET', body } = {}) {
    const accessToken = await this.credential.getToken(scope)
    if (!accessToken?.token) throw error('AZURE_AUTH', `Azure did not return a token for ${scope}`)
    const response = await this.fetchImpl(url, {
      method,
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${accessToken.token}`,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
    const text = await response.text()
    let value = null
    if (text) {
      try {
        value = JSON.parse(text)
      } catch {
        value = text
      }
    }
    if (!response.ok) {
      const message = value?.error?.message || value?.message || text || `Azure request failed (${response.status})`
      const cause = error(value?.error?.code || 'AZURE_REQUEST_FAILED', message)
      cause.statusCode = response.status
      cause.retryable = response.status === 408 || response.status === 429 || response.status >= 500
      throw cause
    }
    return value
  }
}

function deploymentTemplate() {
  return {
    $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
    contentVersion: '1.0.0.0',
    parameters: {
      DeploySealOperationId: { type: 'string' },
      DeploySealArtifactDigest: { type: 'string' },
    },
    resources: [],
    outputs: {
      DeploySealOperationId: { type: 'string', value: '[parameters(\'DeploySealOperationId\')]' },
      DeploySealArtifactDigest: { type: 'string', value: '[parameters(\'DeploySealArtifactDigest\')]' },
    },
  }
}

function parameterValue(deployment, name) {
  return deployment?.properties?.parameters?.[name]?.value
}

function deploymentEvidence(deployment) {
  return {
    id: deployment?.id || null,
    name: deployment?.name || null,
    provisioningState: deployment?.properties?.provisioningState || null,
    parameters: deployment?.properties?.parameters || null,
    outputs: deployment?.properties?.outputs || null,
  }
}

export class AzureArmProvider {
  constructor({
    subscriptionId = process.env.AZURE_SUBSCRIPTION_ID,
    resourceGroup = process.env.DEPLOYSEAL_AZURE_RESOURCE_GROUP,
    location = process.env.DEPLOYSEAL_AZURE_LOCATION || 'eastus',
    targetId = process.env.DEPLOYSEAL_AZURE_TARGET || 'deployseal-azure-demo',
    client = new AzureRestClient(),
    now = Date.now,
  } = {}) {
    if (!subscriptionId || !resourceGroup) {
      throw error('AZURE_PROVIDER_CONFIG', 'AZURE_SUBSCRIPTION_ID and DEPLOYSEAL_AZURE_RESOURCE_GROUP are required')
    }
    this.id = process.env.DEPLOYSEAL_PROVIDER_ID || 'azure-arm'
    this.subscriptionId = subscriptionId
    this.resourceGroup = resourceGroup
    this.location = location
    this.stackName = targetId
    this.client = client
    this.now = now
    this.capabilities = AZURE_ARM_CAPABILITIES
  }

  assertOperation(operationId, operation) {
    if (!OPERATION_ID.test(operationId)) throw error('INVALID_PROVIDER_TOKEN', 'operation id must be 32-byte lowercase hex')
    if (operation?.core?.targetId !== this.stackName) {
      throw error('PROVIDER_TARGET_MISMATCH', 'operation target does not match configured Azure target')
    }
  }

  deploymentUrl(operationId) {
    return `https://management.azure.com/subscriptions/${encodeURIComponent(this.subscriptionId)}/resourcegroups/${encodeURIComponent(this.resourceGroup)}/providers/Microsoft.Resources/deployments/${encodeURIComponent(operationId)}?api-version=${ARM_API_VERSION}`
  }

  async get(operationId) {
    try {
      return await this.client.request(this.deploymentUrl(operationId), { scope: ARM_SCOPE })
    } catch (cause) {
      if (cause.statusCode === 404) return null
      throw cause
    }
  }

  assertBinding(deployment, operationId, operation) {
    if (
      parameterValue(deployment, 'DeploySealOperationId') !== operationId ||
      parameterValue(deployment, 'DeploySealArtifactDigest') !== operation.core.artifactDigest
    ) {
      throw error('PROVIDER_BINDING_MISMATCH', 'Azure deployment parameters do not match the reserved operation')
    }
  }

  execution(deployment, operationId, operation) {
    this.assertBinding(deployment, operationId, operation)
    const status = provisioningStatus(deployment?.properties?.provisioningState)
    const evidence = deploymentEvidence(deployment)
    return {
      operationId,
      providerOperationId: deployment?.id || deployment?.name || operationId,
      actualTarget: this.stackName,
      actualArtifactDigest: parameterValue(deployment, 'DeploySealArtifactDigest'),
      status,
      ...(status === 'PENDING'
        ? {}
        : { completedAt: asIso(deployment?.properties?.timestamp, this.now) }),
      providerEvidenceHash: sha256Hex(JSON.stringify(evidence)),
      azureDeploymentId: deployment?.id || null,
    }
  }

  async execute({ operationId, operation }) {
    this.assertOperation(operationId, operation)
    const existing = await this.get(operationId)
    if (existing) return this.execution(existing, operationId, operation)

    let deployment
    try {
      deployment = await this.client.request(this.deploymentUrl(operationId), {
        scope: ARM_SCOPE,
        method: 'PUT',
        body: {
          properties: {
            mode: 'Incremental',
            template: deploymentTemplate(),
            parameters: {
              DeploySealOperationId: { value: operationId },
              DeploySealArtifactDigest: { value: operation.core.artifactDigest },
            },
          },
        },
      })
    } catch (cause) {
      throw Object.assign(cause, { retryable: true })
    }

    if (!deployment?.properties) {
      return {
        operationId,
        providerOperationId: deployment?.id || operationId,
        actualTarget: this.stackName,
        actualArtifactDigest: operation.core.artifactDigest,
        status: 'PENDING',
      }
    }
    return this.execution(deployment, operationId, operation)
  }

  async query({ operationId, operation }) {
    this.assertOperation(operationId, operation)
    const deployment = await this.get(operationId)
    return deployment ? this.execution(deployment, operationId, operation) : null
  }
}

export class AzureKeyVaultReceiptSigner {
  constructor({
    vaultUrl = process.env.AZURE_KEY_VAULT_URL,
    keyName = process.env.DEPLOYSEAL_AZURE_KEY_NAME,
    keyVersion = process.env.DEPLOYSEAL_AZURE_KEY_VERSION,
    algorithm = process.env.DEPLOYSEAL_AZURE_KEY_ALGORITHM || 'PS256',
    client = new AzureRestClient(),
  } = {}) {
    if (!vaultUrl || !keyName) throw error('AZURE_KEY_VAULT_CONFIG', 'AZURE_KEY_VAULT_URL and DEPLOYSEAL_AZURE_KEY_NAME are required')
    if (!['PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512'].includes(algorithm)) {
      throw error('AZURE_KEY_ALGORITHM', `unsupported Azure Key Vault signing algorithm: ${algorithm}`)
    }
    this.vaultUrl = vaultUrl.replace(/\/$/u, '')
    this.keyName = keyName
    this.keyVersion = keyVersion
    this.algorithm = algorithm
    this.client = client
    this.keyUrlPromise = null
    this.id = `${this.vaultUrl}/keys/${encodeURIComponent(this.keyName)}${keyVersion ? `/${encodeURIComponent(keyVersion)}` : ''}`
  }

  async keyUrl() {
    if (this.keyVersion) return this.id
    this.keyUrlPromise ||= this.client
      .request(`${this.vaultUrl}/keys/${encodeURIComponent(this.keyName)}?api-version=${KEY_VAULT_API_VERSION}`, {
        scope: KEY_VAULT_SCOPE,
      })
      .then((key) => {
        const id = key?.key?.kid || key?.kid
        if (!id) throw error('AZURE_KEY_NOT_FOUND', 'Azure Key Vault did not return a key id')
        this.id = id
        return id
      })
    return this.keyUrlPromise
  }

  async sign(message) {
    const response = await this.client.request(`${await this.keyUrl()}/sign?api-version=${KEY_VAULT_API_VERSION}`, {
      scope: KEY_VAULT_SCOPE,
      method: 'POST',
      body: { alg: this.algorithm, value: encodeBase64Url(message) },
    })
    if (!response?.value) throw error('AZURE_KEY_NO_SIGNATURE', 'Azure Key Vault returned no receipt signature')
    if (response.kid) this.id = response.kid
    return decodeBase64Url(response.value)
  }

  async verify(message, signature) {
    const response = await this.client.request(`${await this.keyUrl()}/verify?api-version=${KEY_VAULT_API_VERSION}`, {
      scope: KEY_VAULT_SCOPE,
      method: 'POST',
      body: {
        alg: this.algorithm,
        value: encodeBase64Url(message),
        signature: encodeBase64Url(signature),
      },
    })
    return response?.value === true
  }
}

function attestationClaim(payload, name) {
  return payload?.[name] ?? payload?.['x-ms-isolation-tee']?.[name]
}

function checkAttestationClaims(payload) {
  if (payload?.['x-ms-attestation-type'] !== 'sevsnpvm') {
    throw error('AZURE_ATTESTATION_TYPE', 'Azure attestation is not an AMD SEV-SNP VM token')
  }
  if (attestationClaim(payload, 'x-ms-compliance-status') !== 'azure-compliant-cvm') {
    throw error('AZURE_ATTESTATION_COMPLIANCE', 'Azure attestation did not report an Azure-compliant CVM')
  }
  if (attestationClaim(payload, DEBUGGABLE_CLAIM) !== false) {
    throw error('AZURE_ATTESTATION_DEBUG', 'debuggable Azure confidential VMs are rejected')
  }
  const measurement = attestationClaim(payload, MEASUREMENT_CLAIM)
  if (typeof measurement !== 'string' || !measurement || /^0+$/u.test(measurement)) {
    throw error('AZURE_ATTESTATION_MEASUREMENT', 'Azure attestation did not include a launch measurement')
  }
  return measurement
}

async function verifyMaaToken(token, { endpoint, fetchImpl = globalThis.fetch, now = Date.now } = {}) {
  if (typeof token !== 'string') throw error('INVALID_ATTESTATION_TOKEN', 'Azure attestation token is required')
  const [encodedHeader, encodedPayload, encodedSignature] = token.split('.')
  if (!encodedHeader || !encodedPayload || !encodedSignature) throw error('INVALID_ATTESTATION_TOKEN', 'Azure attestation token is not a JWT')
  const header = jsonFrom(decodeBase64Url(encodedHeader).toString('utf8'), 'Azure attestation header')
  const payload = jsonFrom(decodeBase64Url(encodedPayload).toString('utf8'), 'Azure attestation payload')
  if (!['RS256', 'RS384', 'RS512'].includes(header.alg)) throw error('INVALID_ATTESTATION_TOKEN', 'unsupported Azure attestation signature algorithm')

  const certsUrl = process.env.DEPLOYSEAL_AZURE_ATTESTATION_CERTS_URL || header.jku
  if (!certsUrl) throw error('INVALID_ATTESTATION_TOKEN', 'Azure attestation token has no signing-key URL')
  const keyUrl = new URL(certsUrl)
  if (keyUrl.protocol !== 'https:' || !keyUrl.hostname.endsWith('.attest.azure.net')) {
    throw error('INVALID_ATTESTATION_TOKEN', 'Azure attestation signing-key URL is not an Azure Attestation endpoint')
  }
  if (typeof fetchImpl !== 'function') throw error('AZURE_HTTP_CONFIG', 'global fetch is required for attestation')
  const response = await fetchImpl(keyUrl, { headers: { accept: 'application/json' } })
  if (!response.ok) throw error('AZURE_ATTESTATION_KEYS', `unable to fetch Azure attestation signing keys (${response.status})`)
  const keySet = await response.json()
  const jwk = keySet.keys?.find((key) => key.kid === header.kid)
  if (!jwk) throw error('AZURE_ATTESTATION_KEYS', 'Azure attestation signing key was not found')
  const verifier = createVerify(header.alg === 'RS256' ? 'RSA-SHA256' : header.alg === 'RS384' ? 'RSA-SHA384' : 'RSA-SHA512')
  verifier.update(`${encodedHeader}.${encodedPayload}`)
  verifier.end()
  if (!verifier.verify(createPublicKey({ key: jwk, format: 'jwk' }), decodeBase64Url(encodedSignature))) {
    throw error('INVALID_ATTESTATION_TOKEN', 'Azure attestation token signature is invalid')
  }

  const current = Math.floor(now() / 1000)
  if (Number.isFinite(payload.exp) && current > payload.exp + 60) throw error('AZURE_ATTESTATION_EXPIRED', 'Azure attestation token is expired')
  if (Number.isFinite(payload.nbf) && current + 60 < payload.nbf) throw error('AZURE_ATTESTATION_NOT_YET_VALID', 'Azure attestation token is not active yet')
  if (endpoint && payload.iss && payload.iss !== new URL(endpoint).origin) {
    throw error('AZURE_ATTESTATION_ISSUER', 'Azure attestation token issuer does not match the configured endpoint')
  }
  const measurement = checkAttestationClaims(payload)
  return { measurement, claims: payload }
}

export class AzureTeeAttestation {
  constructor({ token, measurement, claims }) {
    this.token = token
    this.measurement = measurement
    this.claims = claims
  }

  static async fromEnv({ fetchImpl = globalThis.fetch } = {}) {
    const token = process.env.DEPLOYSEAL_AZURE_ATTESTATION_TOKEN ||
      (process.env.DEPLOYSEAL_AZURE_ATTESTATION_TOKEN_FILE
        ? readFileSync(process.env.DEPLOYSEAL_AZURE_ATTESTATION_TOKEN_FILE, 'utf8').trim()
        : null)
    if (!token) throw error('AZURE_ATTESTATION_CONFIG', 'DEPLOYSEAL_AZURE_ATTESTATION_TOKEN_FILE is required for Azure provider mode')
    const endpoint = process.env.DEPLOYSEAL_AZURE_ATTESTATION_ENDPOINT
    const result = await verifyMaaToken(token, { endpoint, fetchImpl })
    return new AzureTeeAttestation({ token, ...result })
  }
}
