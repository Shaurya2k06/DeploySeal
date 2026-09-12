import { existsSync, readFileSync } from 'node:fs'

const secretDirectory = process.env.DEPLOYSEAL_AZURE_SECRET_DIR || '/etc/deployseal/secrets'
const secrets = {
  'midnight-seed': 'DEPLOYSEAL_MIDNIGHT_SEED_HEX',
  'midnight-password': 'DEPLOYSEAL_MIDNIGHT_PRIVATE_STATE_PASSWORD',
  'policy-salt': 'DEPLOYSEAL_PRIVATE_POLICY_SALT_HEX',
  'policy-json': 'DEPLOYSEAL_PRIVATE_POLICY_JSON',
  'server-policy-json': 'DEPLOYSEAL_POLICY_JSON',
  'server-evidence-json': 'DEPLOYSEAL_EVIDENCE_JSON',
  'contract-address': 'DEPLOYSEAL_MIDNIGHT_CONTRACT_ADDRESS',
  'build-fact-json': 'DEPLOYSEAL_BUILD_FACT_FILE',
  'build-adapter-public-key': 'DEPLOYSEAL_BUILD_ADAPTER_PUBLIC_KEY_FILE',
  'evidence-facts-json': 'DEPLOYSEAL_EVIDENCE_FACTS_FILE',
  'evidence-adapter-public-key': 'DEPLOYSEAL_EVIDENCE_ADAPTER_PUBLIC_KEY_FILE',
}

for (const [name, variable] of Object.entries(secrets)) {
  const path = `${secretDirectory}/${name}`
  if (existsSync(path)) process.env[variable] = readFileSync(path, 'utf8').trim()
}

const { server } = await import('./index.js')
const port = Number(process.env.PORT || 8787)
const host = process.env.HOST || '127.0.0.1'
server.listen(port, host, () => console.log(`DeploySeal Azure broker listening on http://${host}:${port}`))
