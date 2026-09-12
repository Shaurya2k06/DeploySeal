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
npm --prefix server install
npm --prefix client install

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
compact update 0.34.0
npm --prefix contracts/deployseal run compact
```

The contract binds a policy root, checks a private policy-root witness, and
inserts a one-use operation nullifier. The richer production circuits and
MidnightJS/Testkit path remain gated by the network/toolchain inputs recorded
in `plan.md`.

## Trust boundary

The browser never decides policy and receives only the public operation view.
The local broker evaluates synthetic evidence, persists the provider token
before execution, signs a canonical receipt with an ephemeral Ed25519 key,
and exposes only explicitly selected audit fields. The emulator is intentionally
not a production security boundary; production needs the Midnight proof,
CloudFormation idempotency/query path, Nitro measurement policy, and KMS key
policy described in `context.md` and `plan.md`.

The useful demo sequence is: **Run crash-safe demo → Recover operation →
Receipt → Verify signature → Audit → Create scoped bundle**. The adversarial
buttons show policy rejection before provider invocation and replay rejection
after finalization.
