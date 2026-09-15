import { createPublicKey } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { verifyEvidenceBundle } from './evidence.js'

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch (cause) {
    throw new Error(`${label} must contain valid JSON`, { cause })
  }
}

function publicKeys(path) {
  const raw = readFileSync(path, 'utf8')
  try {
    const parsed = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not a key map')
    return Object.fromEntries(Object.entries(parsed).map(([id, value]) => [id, createPublicKey(value)]))
  } catch {
    return createPublicKey(raw)
  }
}

const [bundlePath, keyPath, scopePath] = process.argv.slice(2)
if (!bundlePath || !keyPath || !scopePath) {
  console.error('usage: node src/verify-evidence.js <bundle.json> <public-keys.json-or-pem> <scope.json>')
  process.exitCode = 2
} else {
  try {
    const bundle = readJson(bundlePath, 'bundle')
    const scope = readJson(scopePath, 'scope')
    const facts = verifyEvidenceBundle(bundle, publicKeys(keyPath), scope)
    console.log(JSON.stringify({ valid: true, facts: facts.map(({ kind, role, signerKeyId }) => ({ kind, role, signerKeyId })) }, null, 2))
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
