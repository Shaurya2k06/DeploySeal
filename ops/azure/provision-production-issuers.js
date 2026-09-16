import { createPublicKey } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const subscriptionId = process.env.AZURE_SUBSCRIPTION_ID || '9b6559f4-2b0a-4e2a-8f77-b1f72d8310d8'
const resourceGroup = process.env.DEPLOYSEAL_ISSUER_RESOURCE_GROUP || 'deployseal-azure-rg'
const location = process.env.DEPLOYSEAL_AZURE_LOCATION || 'eastus'
const coordinatorVault = process.env.AZURE_KEY_VAULT_NAME || 'deploysealkv260912'
const issuerDefinitions = [
  { kind: 'sbom', role: 'supply-chain', identityName: 'deployseal-issuer-sbom', vaultName: 'dsevidsbom260912', keyName: 'deployseal-production-sbom-v1' },
  { kind: 'model-eval', role: 'release-validation', identityName: 'deployseal-issuer-model-eval', vaultName: 'dsevidmodel260912', keyName: 'deployseal-production-model-v1' },
  { kind: 'residency', role: 'azure-residency', identityName: 'deployseal-issuer-residency', vaultName: 'dsevidres260912', keyName: 'deployseal-production-residency-v1' },
  { kind: 'approval', role: 'security', identityName: 'deployseal-issuer-security', vaultName: 'dsevidsec260912', keyName: 'deployseal-production-security-v1' },
  { kind: 'approval', role: 'governance', identityName: 'deployseal-issuer-governance', vaultName: 'dsevidgov260912', keyName: 'deployseal-production-governance-v1' },
]

function az(args, quiet = false) {
  return execFileSync('az', [...args, '--only-show-errors'], quiet
    ? { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
    : { encoding: 'utf8' }).trim()
}

function readJson(args) {
  return JSON.parse(az([...args, '--output', 'json']))
}

function findJson(args) {
  try {
    return JSON.parse(az([...args, '--output', 'json'], true))
  } catch {
    return null
  }
}

function publicKeyPem(jwk) {
  return createPublicKey({ key: jwk, format: 'jwk' }).export({ format: 'pem', type: 'spki' }).toString()
}

function ensureIdentity(definition) {
  return findJson(['identity', 'show', '--resource-group', resourceGroup, '--name', definition.identityName]) || readJson([
    'identity', 'create', '--resource-group', resourceGroup, '--name', definition.identityName,
    '--location', location, '--subscription', subscriptionId,
    '--tags', 'deploysealIssuer=production', `issuerRole=${definition.role}`,
  ])
}

function ensureVault(definition, operatorObjectId) {
  const existing = findJson(['keyvault', 'show', '--name', definition.vaultName, '--subscription', subscriptionId])
  if (!existing) {
    readJson([
      'keyvault', 'create', '--resource-group', resourceGroup, '--name', definition.vaultName,
      '--location', location, '--sku', 'standard', '--enable-rbac-authorization', 'false',
      '--subscription', subscriptionId, '--tags', 'deploysealIssuer=production', `issuerRole=${definition.role}`,
    ])
  }
  az(['keyvault', 'set-policy', '--name', definition.vaultName, '--object-id', operatorObjectId, '--key-permissions', 'get', 'list', 'create', 'sign', 'verify'])
}

function ensureKey(definition) {
  return findJson(['keyvault', 'key', 'show', '--vault-name', definition.vaultName, '--name', definition.keyName]) || readJson([
    'keyvault', 'key', 'create', '--vault-name', definition.vaultName, '--name', definition.keyName,
    '--kty', 'RSA', '--size', '2048', '--ops', 'sign', 'verify',
  ])
}

function main() {
  const operatorObjectId = az(['ad', 'signed-in-user', 'show', '--query', 'id', '--output', 'tsv'])
  if (!operatorObjectId) throw new Error('an interactive Azure user is required to provision issuer identities')

  const issuers = issuerDefinitions.map((definition) => {
    const identity = ensureIdentity(definition)
    ensureVault(definition, operatorObjectId)
    az(['keyvault', 'set-policy', '--name', definition.vaultName, '--object-id', identity.principalId, '--key-permissions', 'get', 'sign', 'verify'])
    const key = ensureKey(definition)
    const publicKey = publicKeyPem(key.key)
    return {
      kind: definition.kind,
      role: definition.role,
      keyId: definition.keyName,
      identity: {
        name: identity.name,
        clientId: identity.clientId,
        principalId: identity.principalId,
        resourceId: identity.id,
      },
      keyVault: {
        name: definition.vaultName,
        url: `https://${definition.vaultName}.vault.azure.net`,
        keyName: definition.keyName,
      },
      publicKey,
    }
  })

  const registry = {
    version: 1,
    issuerClass: 'production',
    subscriptionId,
    resourceGroup,
    issuers,
  }
  const publicKeys = Object.fromEntries(issuers.map(({ keyId, publicKey }) => [keyId, publicKey]))
  const directory = mkdtempSync(join(tmpdir(), 'deployseal-production-issuers-'))
  try {
    const registryPath = join(directory, 'production-issuer-registry.json')
    writeFileSync(registryPath, `${JSON.stringify(registry, null, 2)}\n`, { mode: 0o600 })
    az(['keyvault', 'secret', 'set', '--vault-name', coordinatorVault, '--name', 'production-issuer-registry-json', '--file', registryPath, '--content-type', 'application/json'])
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
  console.log(JSON.stringify({
    vault: coordinatorVault,
    issuerClass: registry.issuerClass,
    issuers: issuers.map(({ kind, role, keyId, identity, keyVault }) => ({ kind, role, keyId, identity, keyVault })),
    publicKeys,
  }, null, 2))
}

try {
  main()
} catch (error) {
  console.error(error.message)
  process.exitCode = 1
}
