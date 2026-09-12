# DeploySeal

DeploySeal is a release-control console for proving a deployment policy before
an external provider is allowed to act. The local demo and the live Azure path
show the same recovery sequence: reserve an operation, lose the provider
response, recover with the same idempotency token, verify the receipt, and
reject replay.

The local broker is deliberately labeled an emulator. It does not claim a
Midnight network transaction, Azure execution, SEV-SNP attestation, or
production Key Vault isolation.

The current public Azure demo is
`http://deployseal-cvm-260912.eastus.cloudapp.azure.com/`. It runs on an AMD
SEV-SNP Confidential VM with Azure Attestation, ARM resource-group tag
reconciliation, SQLite durable state, and a Key Vault-signed receipt. The
standard Key Vault software key is not an HSM or Secure Key Release binding;
the public HTTP demo also has no user authentication.

## Run the demo

Use Node 24.11.1+ for the pinned Compact toolchain.

```sh
npm --prefix client install
npm --prefix contracts/deployseal install
npm --prefix server install

# terminal 1
npm --prefix server start

# terminal 2
npm --prefix client run dev
```

Open the Vite URL printed by the client. The default API is
`http://127.0.0.1:8787`; set `PORT` or `VITE_API_URL` when those ports are
already in use.

## Checks

```sh
npm --prefix server test
npm --prefix client run lint
npm --prefix client run build
npm --prefix contracts/deployseal test
```

## Compact contract

The minimal Compact vertical slice lives in
`contracts/deployseal/src/deployseal.compact`. Install the official Compact
tool, select the pinned toolchain, then compile it:

```sh
compact update 0.31.1
npm --prefix contracts/deployseal run compact
```

The Preprod client uses ledger-v8 8.1.0, MidnightJS 4.1.1, and Wallet SDK
DUST 4.2.0. Its first full DUST sync can take a few minutes; the encrypted
wallet snapshot under `.deployseal-midnight-level-db/` makes later runs resume
from the latest indexed event.

The contract binds a policy root, checks a private policy-root witness, binds
the operation digest and policy epoch, inserts a one-use operation nullifier,
and records one terminal receipt hash per operation. The checked-in server
uses these circuits through the local Compact simulator. The same generated
bindings also drive the MidnightJS/Preprod client.

## Midnight Preprod path

The contract package includes real wallet, proof-server, indexer, private-state,
deploy, reserve, and finalize wiring. It needs a funded Preprod wallet and
private policy inputs; keep all values in the environment or a secret manager:

```sh
export DEPLOYSEAL_MIDNIGHT_SEED_HEX='...'
# Needed by deploy/reserve/finalize; the bounded dust command does not need it.
export DEPLOYSEAL_MIDNIGHT_PRIVATE_STATE_PASSWORD='Use-a-strong-Secret-9!'
export DEPLOYSEAL_MIDNIGHT_DB_PATH="$PWD/.deployseal-midnight-level-db"
export DEPLOYSEAL_PRIVATE_POLICY_SALT_HEX='64 lowercase hex characters'
export DEPLOYSEAL_PRIVATE_POLICY_JSON='{"maxCriticalCves":0,"maxHighCves":2,"minEvalScore":90,"minimumApprovals":2}'
export DEPLOYSEAL_EVIDENCE_JSON='{"criticalCves":0,"highCves":1,"evalScore":97,"approvalRoles":["security","governance"]}'

# Run a local proof server before the wallet can submit the DUST-registration transaction.
# docker run --rm -p 6300:6300 midnightntwrk/proof-server:8.1.0 midnight-proof-server -v
export DEPLOYSEAL_MIDNIGHT_PROOF='http://127.0.0.1:6300'
npm --prefix contracts/deployseal run preprod -- dust
# returns a finalized registrationTxId; DUST accrues for the designated address after confirmation

npm --prefix contracts/deployseal run preprod -- deploy
export DEPLOYSEAL_MIDNIGHT_CONTRACT_ADDRESS='returned contract address'
```

For a release, set `DEPLOYSEAL_OPERATION_CORE_JSON` to the canonical operation
JSON and run `preprod -- reserve`; after the provider receipt is available, set
`DEPLOYSEAL_RECEIPT_HASH_HEX` and run `preprod -- finalize`. Both commands
check public nullifier/receipt state first, so a lost response can be retried
without submitting a second circuit call.

The `preprod -- dust` command only syncs the address-specific tNIGHT view and
submits the registration transaction. It intentionally avoids replaying the
entire public DUST event history, which can exceed a local Node heap on a fresh
wallet; DUST generation continues on-chain after the registration is finalized.

To run the HTTP broker against those same Midnight private-state files, set
`DEPLOYSEAL_PROVIDER=azure-arm`, the Azure variables below, and both
`DEPLOYSEAL_MIDNIGHT_CONTRACT_ADDRESS` and `DEPLOYSEAL_MIDNIGHT_SEED_HEX`.
The broker then uses the real reserve/finalize client; if those credentials are
missing it refuses the real Azure path instead of falling back to the simulator.

## Real Azure mode

Set `DEPLOYSEAL_PROVIDER=azure-arm` to select the Azure Resource Manager
adapter. It requires `AZURE_SUBSCRIPTION_ID`,
`DEPLOYSEAL_AZURE_RESOURCE_GROUP`, `DEPLOYSEAL_AZURE_LOCATION`,
`DEPLOYSEAL_AZURE_TARGET`, `AZURE_KEY_VAULT_URL`,
`DEPLOYSEAL_AZURE_KEY_NAME`, and a signed Azure Attestation JWT in
`DEPLOYSEAL_AZURE_ATTESTATION_TOKEN_FILE`. The managed identity running the
broker needs deployment permission only in the configured target resource
group and Key Vault sign/verify permission for the receipt key.

The Azure adapter uses the operation ID as the ARM deployment name, applies
operation and artifact tags to the isolated target resource group, queries
that same deployment after a lost response, and signs the receipt digest with
Key Vault. The recommended runtime is an AMD SEV-SNP `Standard_DC2as_v5`
Confidential VM. Generate the attestation JWT inside that VM with Microsoft's
`azure-guest-attest` tool; the server verifies the MAA signature, requires an
Azure-compliant non-debuggable SEV-SNP claim, checks an allowlisted launch
measurement and fresh challenge-bound runtime data, and binds the measurement
to the receipt.

## Trust boundary

The browser never decides policy and receives only the public operation view.
The local broker evaluates synthetic evidence and uses the checked-in Compact
simulator; Azure mode requires a signed GitHub `BuildFactV1`, verifies the
attestation challenge inside the CVM, reconciles ARM tags, persists through a
SQLite lease, and signs the canonical receipt with Key Vault. Optional signed
`EvidenceFactV1` bundles cover SBOM, model-evaluation, residency, and approval
inputs; set `DEPLOYSEAL_REQUIRE_EVIDENCE_FACTS=true` only when those external
issuer keys and facts are provisioned. The public demo remains a demo, not a
fully authenticated production control plane.

The useful demo sequence is: **Run crash-safe demo → Recover operation →
Receipt → Verify signature → Audit → Create scoped bundle**. The adversarial
buttons show policy rejection before provider invocation and replay rejection
after finalization.

## Alternate AWS mode

Set `DEPLOYSEAL_PROVIDER=aws-cloudformation` to select the CloudFormation
adapter. It requires `AWS_REGION`, `DEPLOYSEAL_CF_STACK`,
`DEPLOYSEAL_CF_CHANGE_SET`, `DEPLOYSEAL_KMS_KEY_ID`, and private
`DEPLOYSEAL_POLICY_JSON` / `DEPLOYSEAL_EVIDENCE_JSON` supplied by a secret
manager. The adapter reuses the operation ID as `ClientRequestToken`, queries
the same change set, checks the artifact parameter, and binds the receipt to a
CloudTrail event. It refuses to run without the configured Midnight proof
client; the local Compact simulator is never accepted as a production proof
boundary.

`.github/workflows/deployseal-demo.yml` builds and verifies a GitHub-attested
artifact, obtains a short-lived OIDC token, emits a signed `BuildFactV1`, and
publishes the fact and its public adapter key to the Azure Key Vault used by
the coordinator. The VM refreshes those secrets and restarts the broker when a
new fact arrives.
The coordinator-side OIDC/BuildFact verifier is in `server/src/github.js` and
uses `gh attestation verify` for the Sigstore attestation boundary. Supply the
fact through `DEPLOYSEAL_BUILD_FACT_FILE` and its separately allowlisted
`DEPLOYSEAL_BUILD_ADAPTER_PUBLIC_KEY_FILE`; the workflow requires the matching
persistent `DEPLOYSEAL_BUILD_ADAPTER_PRIVATE_KEY` repository secret. The server
binds the fact's commit, repository, and artifact digest to the operation it
creates. Generate the pair once, keep the private key only in GitHub Secrets,
and give the public key to the coordinator:

```sh
openssl genpkey -algorithm ED25519 -out deployseal-build-adapter.pem
openssl pkey -in deployseal-build-adapter.pem -pubout -out deployseal-build-adapter.pub.pem
gh secret set DEPLOYSEAL_BUILD_ADAPTER_PRIVATE_KEY < deployseal-build-adapter.pem
export DEPLOYSEAL_BUILD_ADAPTER_PUBLIC_KEY_FILE="$PWD/deployseal-build-adapter.pub.pem"
```

Verify a local receipt from the durable state without loading the broker:

```sh
npm --prefix server run verify-receipt -- /tmp/deployseal-state.json
```
