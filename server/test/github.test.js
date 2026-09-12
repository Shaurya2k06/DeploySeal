import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import { test } from 'node:test'
import {
  buildFactFromVerifiedInputs,
  validateBuildFact,
  verifyBuildFact,
  verifyGithubOidc,
} from '../src/github.js'

function token(header, claims, privateKey) {
  const part = (value) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const signingInput = `${part(header)}.${part(claims)}`
  const signature = sign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url')
  return `${signingInput}.${signature}`
}

test('GitHub OIDC verification binds immutable run claims and a signed BuildFact', async () => {
  const oidcKeys = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const adapterKeys = generateKeyPairSync('ed25519')
  const claims = {
    iss: 'https://token.actions.githubusercontent.com',
    aud: 'deployseal',
    repository_id: '123456789',
    workflow: 'deployseal-demo.yml',
    workflow_ref: 'Shaurya2k06/DeploySeal/.github/workflows/deployseal-demo.yml@refs/heads/main',
    job_workflow_ref: 'Shaurya2k06/DeploySeal/.github/workflows/deployseal-demo.yml@refs/heads/main',
    environment: 'staging',
    run_id: '987654321',
    run_attempt: '1',
    sha: 'a'.repeat(40),
    iat: 1000,
    exp: 1300,
  }
  const tokenValue = token({ alg: 'RS256', kid: 'github-key-1', typ: 'JWT' }, claims, oidcKeys.privateKey)
  const verifiedClaims = await verifyGithubOidc(tokenValue, {
    jwks: { keys: [{ ...oidcKeys.publicKey.export({ format: 'jwk' }), kid: 'github-key-1', alg: 'RS256' }] },
    expected: {
      audience: 'deployseal',
      repositoryId: 123456789,
      workflow: claims.workflow,
      workflowRef: claims.workflow_ref,
      environment: 'staging',
      commitSha: claims.sha,
      runId: 987654321,
      runAttempt: 1,
    },
    now: 1100,
  })

  const fact = buildFactFromVerifiedInputs({
    token: tokenValue,
    claims: verifiedClaims,
    attestation: {
      verified: true,
      subjectDigest: `sha256:${'b'.repeat(64)}`,
      repository: 'Shaurya2k06/DeploySeal',
      workflow: claims.workflow,
      commitSha: claims.sha,
      runId: claims.run_id,
      runAttempt: claims.run_attempt,
    },
    expected: { artifactDigest: `sha256:${'b'.repeat(64)}`, repository: 'Shaurya2k06/DeploySeal' },
    adapterKeyId: 'build-adapter-1',
    adapterPrivateKey: adapterKeys.privateKey,
    adapterPublicKey: adapterKeys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
  })

  assert.equal(fact.immutableRepositoryId, 123456789)
  assert.equal(fact.artifactDigest, 'b'.repeat(64))
  assert.equal(verifyBuildFact(fact, adapterKeys.publicKey), true)
  assert.equal(fact.adapterPublicKey, adapterKeys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'))
  assert.doesNotThrow(() => validateBuildFact(fact, 1100))
  assert.throws(() => validateBuildFact(fact, 1400), /outside its validity window/u)
  assert.equal(verifyBuildFact({ ...fact, artifactDigest: 'c'.repeat(64) }, adapterKeys.publicKey), false)
  assert.equal(verifyBuildFact({ ...fact, adapterPublicKey: 'bad-key' }, adapterKeys.publicKey), false)
  await assert.rejects(
    verifyGithubOidc(tokenValue, {
      jwks: { keys: [{ ...oidcKeys.publicKey.export({ format: 'jwk' }), kid: 'github-key-1', alg: 'RS256' }] },
      expected: { audience: 'wrong-audience' },
      now: 1100,
    }),
    /claims do not match/u,
  )
  await assert.rejects(
    verifyGithubOidc(tokenValue, {
      jwks: { keys: [{ ...oidcKeys.publicKey.export({ format: 'jwk' }), kid: 'github-key-1', alg: 'RS256' }] },
      now: 1100,
    }),
    /audience is required/u,
  )
})
