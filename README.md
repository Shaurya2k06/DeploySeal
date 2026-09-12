# DeploySeal

DeploySeal is a release-control console for proving a deployment policy before
an external provider is allowed to act. The checked-in demo runs locally and
shows the complete recovery path: reserve an operation, lose the provider
response, recover with the same idempotency token, verify the receipt, and
reject replay.

The local broker is deliberately labeled an emulator. It does not claim a
Midnight network transaction, AWS execution, Nitro attestation, or production
KMS isolation.

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

The contract binds a policy root, checks a private policy-root witness, inserts
a one-use operation nullifier, and records one terminal receipt hash. The
checked-in server uses these circuits through the local Compact simulator. The
same generated bindings also drive the credential-gated MidnightJS/Preprod
client.

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
`DEPLOYSEAL_PROVIDER=aws-cloudformation`, the AWS variables below, and both
`DEPLOYSEAL_MIDNIGHT_CONTRACT_ADDRESS` and `DEPLOYSEAL_MIDNIGHT_SEED_HEX`.
The broker then uses the real reserve/finalize client; if those credentials are
missing it refuses the real AWS path instead of falling back to the simulator.

## Trust boundary

The browser never decides policy and receives only the public operation view.
The local broker evaluates synthetic evidence, runs the checked-in Compact
reservation circuit in its simulator, persists the provider token before
execution, signs a canonical receipt with an ephemeral Ed25519 key,
and exposes only explicitly selected audit fields. The emulator is intentionally
not a production security boundary; production needs the Midnight proof,
CloudFormation idempotency/query path, Nitro measurement policy, and KMS key
policy described in `context.md` and `plan.md`.

The useful demo sequence is: **Run crash-safe demo → Recover operation →
Receipt → Verify signature → Audit → Create scoped bundle**. The adversarial
buttons show policy rejection before provider invocation and replay rejection
after finalization.

## Real AWS mode

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
artifact, obtains a short-lived OIDC token, and emits a signed `BuildFactV1`.
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
