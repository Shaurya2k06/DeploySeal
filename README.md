# DeploySeal

DeploySeal is a release-control console. A private Compact policy proof
authorizes one provider operation, the broker recovers the same operation after
a lost response, and a signed receipt records the result without exposing the
policy evidence.

## Public deployment

- [Landing page](https://deployseal.vercel.app/)
- [End-to-end demo](https://deployseal.vercel.app/demo)
- [Azure broker health](https://deployseal.vercel.app/api/health)
- [Midnight Preprod contract](https://preprod.midnightexplorer.com/contracts/0x011e650ec7885e33e40bcb9c2393417e0dc7afff61b33ecaffcbebe59a79c6b7)

The public Vercel client proxies `/api` through the server-side gateway in
`api/[...path].js` to the Azure SEV-SNP CVM. The Azure path uses MAA
attestation, Azure Resource Manager, SQLite durable state, a Midnight Preprod
contract, and an Azure Key Vault signing key.

The checked-in broker supports bearer authentication and direct HTTPS when
`DEPLOYSEAL_API_TOKEN`, `DEPLOYSEAL_REQUIRE_AUTH=true`,
`DEPLOYSEAL_REQUIRE_TLS=true`, `DEPLOYSEAL_TLS_KEY_FILE`, and
`DEPLOYSEAL_TLS_CERT_FILE` are configured. For the public Azure VM, run
`ops/azure/secure-live.sh <public-host> <client-origin>` after storing the
`api-token` secret in Key Vault. It installs HTTPS termination in Nginx and
keeps the bearer token server-side in Vercel.

If a trusted reverse proxy terminates TLS before Node, set
`DEPLOYSEAL_TLS_TERMINATED=true` and keep the proxy-to-broker hop private.

## Repository layout

| Path | Purpose |
| --- | --- |
| `api/` | Server-side Vercel gateway for the authenticated Azure broker |
| `client/` | Vite/React landing page and live release console |
| `server/` | Node broker, protocol, provider adapters, receipt verifier, and tests |
| `contracts/deployseal/` | Compact reserve/finalize contract, generated assets, and Preprod client |
| `ops/azure/` | Azure CVM bootstrap, secure rollout, evidence publication, and live upgrade scripts |
| `.github/workflows/` | Checks plus GitHub-attested BuildFact publication to Azure Key Vault |

## Run locally

Use Node `24.11.1` or newer.

```sh
npm ci --prefix contracts/deployseal
npm ci --prefix server
npm ci --prefix client

# terminal 1
npm --prefix server start

# terminal 2
npm --prefix client run dev
```

The broker has no local provider, Compact, attestation, or receipt-key fallback.
Configure a real Azure or AWS provider and a funded Midnight Preprod wallet
before starting it. The local client uses `http://127.0.0.1:8787`; set
`VITE_API_URL` if the broker runs elsewhere.

Run the checks with:

```sh
npm --prefix contracts/deployseal test
npm --prefix server test
npm --prefix client run lint
npm --prefix client run build
```

## Compact and Midnight Preprod

The checked-in contract is
`contracts/deployseal/src/deployseal.compact`. With the official Compact CLI:

```sh
compact update 0.31.1
npm --prefix contracts/deployseal run compact
```

The Preprod client needs a funded wallet, private policy inputs, and a
password-protected private-state directory. Keep all values in a secret manager
or the shell environment:

```sh
export DEPLOYSEAL_MIDNIGHT_SEED_HEX='...'
export DEPLOYSEAL_MIDNIGHT_PRIVATE_STATE_PASSWORD='Use-a-strong-secret'
export DEPLOYSEAL_MIDNIGHT_DB_PATH="$PWD/.deployseal-midnight-level-db"
export DEPLOYSEAL_PRIVATE_POLICY_SALT_HEX='64 lowercase hex characters'
export DEPLOYSEAL_PRIVATE_POLICY_JSON='{"maxCriticalCves":0,"maxHighCves":2,"minEvalScore":90,"minimumApprovals":2}'
export DEPLOYSEAL_EVIDENCE_JSON="$(cat /secure/path/private-evidence.json)"
```

`DEPLOYSEAL_EVIDENCE_JSON` must come from the trusted private evaluator; do not
commit sample values or use it as a substitute for signed issuer facts.

Provider mode also requires a signed `EvidenceFactV1` bundle and trusted
issuer key in `DEPLOYSEAL_EVIDENCE_FACTS_JSON` and
`DEPLOYSEAL_EVIDENCE_ADAPTER_PUBLIC_KEY`.

Each issuer can sign a fact from its real payload and ciphertext files:

```sh
npm --prefix server run issue-evidence -- --kind sbom --role supply-chain \
  --schema-id deployseal/sbom --schema-version 1 \
  --subject-artifact-digest <sha256> --scope-file scope.json \
  --payload-file sbom.json --ciphertext-file sbom.enc \
  --signer-key-id sbom-issuer-v1 --private-key-file sbom.key \
  --output sbom.fact.json
```

The issuer must provide the payload, ciphertext, and signing key; the command
does not generate evidence values. Verify and publish an assembled bundle with:

```sh
ops/azure/publish-evidence.sh evidence-facts.json evidence-public-keys.json scope.json
```

Set `DEPLOYSEAL_MIDNIGHT_PROOF` to a reachable proof server, then use the
credential-gated commands:

```sh
npm --prefix contracts/deployseal run preprod -- dust
npm --prefix contracts/deployseal run preprod -- deploy
export DEPLOYSEAL_MIDNIGHT_CONTRACT_ADDRESS='returned contract address'
npm --prefix contracts/deployseal run preprod -- reserve
npm --prefix contracts/deployseal run preprod -- finalize
```

`dust` registers eligible tNIGHT UTXOs and returns while DUST accrues on-chain.
`reserve` and `finalize` check public state before submitting, so retrying a
lost response does not create a second operation.

For `reserve`, set `DEPLOYSEAL_OPERATION_CORE_JSON` to the canonical operation
JSON. For `finalize`, also set `DEPLOYSEAL_RECEIPT_HASH_HEX` to the 32-byte
receipt hash.

## Azure mode

Set `DEPLOYSEAL_PROVIDER=azure-arm` and provide the Azure subscription,
resource-group, target, location, Key Vault, attestation endpoint/token, and
measurement allowlist variables described in `ops/azure/bootstrap.sh`. The
broker requires a signed GitHub `BuildFactV1` in provider mode. Its managed
identity needs access only to the configured target resource group and Key
Vault signing key.

The Azure adapter binds the operation ID to the ARM deployment name and tags,
reconciles the same deployment after a lost response, verifies the attested
SEV-SNP measurement and challenge, and signs the canonical receipt in Key
Vault. `ops/azure/upgrade-live.sh` refreshes the live VM from `main`.

`.github/workflows/deployseal-demo.yml` verifies the build attestation, signs a
BuildFact with the configured adapter key, publishes it to Key Vault, and can
roll the Azure VM with `ops/azure/upgrade-live.sh`. It does not invent SBOM,
model-evaluation, residency, or approval facts; those must be signed by
independent issuers and published as `evidence-facts-json` plus
`evidence-adapter-public-key`. The broker refuses to start without that
bundle.

For the live demo environment only, `node ops/azure/demo-evidence.js` creates
separate non-exportable Azure Key Vault issuer keys and signs facts from the
checked-in lockfiles, passing release checks, the live Azure region, and the
authenticated operator sessions. These operator-demo approval keys are not a
replacement for independent security and governance issuers in production.

## Other provider

`server/src/aws.js` remains a real alternate CloudFormation/KMS adapter for
consumers that explicitly select `DEPLOYSEAL_PROVIDER=aws-cloudformation`.
Production deployment for this project is Azure-only: ARM replaces the
CloudFormation effect, Key Vault replaces KMS signing, and the existing CVM
provides the attestation boundary. No AWS account-side rollout is required.

## Pending implementation

- The live Azure broker is waiting for the four independent issuer systems to
  supply real SBOM, model-evaluation, residency, and approval payloads,
  ciphertexts, and separate signing keys. Publish the verified bundle with
  `ops/azure/publish-evidence.sh`; the rollout refuses to proceed without it.
- The Azure `api-token`, HTTPS termination, Vercel gateway, and backend URL are
  configured. `/api/health` and the end-to-end demo become live after the
  signed EvidenceFacts bundle is published.

To verify a saved receipt bundle or SQLite state:

```sh
npm --prefix server run verify-receipt -- /path/to/receipt-bundle.json
npm --prefix server run verify-receipt -- /path/to/state.sqlite
```
