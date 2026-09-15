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

The public Vercel client proxies `/api` to the Azure SEV-SNP CVM. The Azure
path uses MAA attestation, Azure Resource Manager, SQLite durable state, a
Midnight Preprod contract, and an Azure Key Vault signing key.

The public demo is intentionally unauthenticated and the Azure VM origin is
HTTP. Do not use it as a production control plane without adding application
authentication and HTTPS at the origin.

## Repository layout

| Path | Purpose |
| --- | --- |
| `client/` | Vite/React landing page and live release console |
| `server/` | Node broker, protocol, provider adapters, receipt verifier, and tests |
| `contracts/deployseal/` | Compact reserve/finalize contract, generated assets, and Preprod client |
| `ops/azure/` | Azure CVM bootstrap, attestation inspection, and live upgrade scripts |
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
export DEPLOYSEAL_EVIDENCE_JSON='{"criticalCves":0,"highCves":1,"evalScore":97,"approvalRoles":["security","governance"]}'
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
BuildFact with the configured adapter key, and publishes the fact and public
key to Key Vault. It does not invent SBOM, model-evaluation, residency, or
approval facts; those remain inputs from independent issuers. The optional
EvidenceFact gate can be enabled with
`DEPLOYSEAL_REQUIRE_EVIDENCE_FACTS=true` once those issuers are provisioned.

## Other provider

`server/src/aws.js` contains the tested CloudFormation/KMS alternate adapter.
It is not the active public deployment. AWS mode still requires the real
Midnight contract, a signed BuildFact, provider evidence, and an explicitly
configured `DEPLOYSEAL_ENCLAVE_MEASUREMENT`.

## Pending implementation

- Independent EvidenceFact issuers for SBOM, model evaluation, residency, and
  approvals. Until those issuers are connected, the operator must supply the
  release evidence inputs through `DEPLOYSEAL_EVIDENCE_JSON`; the optional
  EvidenceFact bundle can be enforced with `DEPLOYSEAL_REQUIRE_EVIDENCE_FACTS=true`.
- Authentication and HTTPS at the public broker origin. The demo remains an
  intentionally unauthenticated showcase.
- Live AWS deployment and operations wiring; the adapter and unit coverage
  exist, but Azure is the only public deployment.

To verify a saved receipt bundle or SQLite state:

```sh
npm --prefix server run verify-receipt -- /path/to/receipt-bundle.json
npm --prefix server run verify-receipt -- /path/to/state.sqlite
```
