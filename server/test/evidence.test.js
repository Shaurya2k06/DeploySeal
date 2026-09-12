import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { test } from 'node:test'
import { signEvidenceFact, verifyEvidenceBundle } from '../src/evidence.js'

const expected = {
  artifactDigest: 'a'.repeat(64),
  commitSha: 'b'.repeat(40),
  providerId: 'azure-arm',
  targetId: 'deployseal-azure-demo',
  region: 'eastus',
  policyEpoch: 1,
}

function bundle(now = Math.floor(Date.now() / 1000)) {
  const publicKeys = {}
  const facts = ['sbom', 'model-eval', 'residency', 'approval'].map((kind, index) => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const signerKeyId = `${kind}-key`
    publicKeys[signerKeyId] = publicKey
    return signEvidenceFact({
      version: 1,
      kind,
      role: kind === 'approval' ? (index === 3 ? 'governance' : 'security') : kind,
      schemaId: `deployseal/${kind}`,
      schemaVersion: 1,
      subjectArtifactDigest: expected.artifactDigest,
      operationScope: { ...expected },
      issuedAt: now - 1,
      expiresAt: now + 300,
      payloadCommitment: String(index + 1).repeat(64),
      evidenceCiphertextHash: String(index + 5).repeat(64),
      signerKeyId,
    }, privateKey)
  })
  return { bundle: { version: 1, facts }, publicKeys }
}

test('EvidenceFactV1 verifies independent signatures and release binding', () => {
  const now = Math.floor(Date.now() / 1000)
  const input = bundle(now)
  assert.equal(verifyEvidenceBundle(input.bundle, input.publicKeys, expected, now).length, 4)

  const mutated = structuredClone(input.bundle)
  mutated.facts[0].operationScope.targetId = 'wrong-target'
  assert.throws(() => verifyEvidenceBundle(mutated, input.publicKeys, expected, now), /bound to a different release/u)

  const missing = { version: 1, facts: input.bundle.facts.filter(({ kind }) => kind !== 'residency') }
  assert.throws(() => verifyEvidenceBundle(missing, input.publicKeys, expected, now), /missing residency/u)
})
