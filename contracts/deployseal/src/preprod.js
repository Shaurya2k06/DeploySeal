import { WebSocket } from 'ws'
import * as Rx from 'rxjs'
import * as ledger from '@midnight-ntwrk/ledger-v8'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { ApiPromise, WsProvider } from '@polkadot/api'
import { CompiledContract } from '@midnight-ntwrk/compact-js'
import { DeploySeal, witnesses } from './index.js'
import { ContractState } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime'
import { setNetworkId, getNetworkId } from '@midnight-ntwrk/midnight-js/network-id'
import { deployContract, findDeployedContract, submitCallTxAsync } from '@midnight-ntwrk/midnight-js/contracts'
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider'
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider'
import { StorageEncryption, levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider'
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider'
import { validatePassword } from '@midnight-ntwrk/midnight-js-utils'
import { SucceedEntirely } from '@midnight-ntwrk/midnight-js-types'
import { WalletFacade } from '@midnightntwrk/wallet-sdk-facade'
import { DustWallet } from '@midnightntwrk/wallet-sdk-dust-wallet'
import { HDWallet, Roles } from '@midnightntwrk/wallet-sdk-hd'
import { ShieldedWallet } from '@midnightntwrk/wallet-sdk-shielded'
import {
  createKeystore,
  PublicKey,
  UnshieldedWallet,
} from '@midnightntwrk/wallet-sdk-unshielded-wallet'
import { InMemoryTransactionHistoryStorage } from '@midnightntwrk/wallet-sdk-abstractions'
import { operationId, operationNullifier } from '../../../server/src/protocol.js'

globalThis.WebSocket = WebSocket

const root = new URL('.', import.meta.url).pathname
const zkConfigPath = `${root}managed/deployseal`
const privateStateId = process.env.DEPLOYSEAL_MIDNIGHT_STATE_ID || 'deployseal-private-state'
const privateStateDb = process.env.DEPLOYSEAL_MIDNIGHT_DB_PATH || new URL('../../../.deployseal-midnight-level-db', import.meta.url).pathname
const dustStatePath = process.env.DEPLOYSEAL_MIDNIGHT_DUST_STATE_PATH || `${privateStateDb}/dust-wallet-state.json`
const network = process.env.DEPLOYSEAL_MIDNIGHT_NETWORK || 'preprod'
const endpoints = {
  indexer: process.env.DEPLOYSEAL_MIDNIGHT_INDEXER || `https://indexer.${network}.midnight.network/api/v4/graphql`,
  indexerWS: process.env.DEPLOYSEAL_MIDNIGHT_INDEXER_WS || `wss://indexer.${network}.midnight.network/api/v4/graphql/ws`,
  node: process.env.DEPLOYSEAL_MIDNIGHT_NODE || `https://rpc.${network}.midnight.network`,
  proof: process.env.DEPLOYSEAL_MIDNIGHT_PROOF || `https://lace-proof-pub.${network}.midnight.network`,
}

function required(name) {
  const value = process.env[name]
  if (!value) throw new Error(`${name} is required`)
  return value
}

function privateStatePassword() {
  const password = required('DEPLOYSEAL_MIDNIGHT_PRIVATE_STATE_PASSWORD')
  try {
    validatePassword(password)
  } catch (cause) {
    throw new Error(`DEPLOYSEAL_MIDNIGHT_PRIVATE_STATE_PASSWORD is invalid: ${cause.message}`, { cause })
  }
  return password
}

async function readDustState() {
  if (!existsSync(dustStatePath)) return undefined
  let record
  try {
    record = JSON.parse(readFileSync(dustStatePath, 'utf8'))
  } catch (cause) {
    throw new Error(`unable to read DUST wallet state at ${dustStatePath}`, { cause })
  }
  if (record?.version !== 1 || typeof record.salt !== 'string' || typeof record.data !== 'string') {
    throw new Error(`invalid DUST wallet state at ${dustStatePath}`)
  }
  const encryption = await StorageEncryption.create(privateStatePassword(), {
    existingSalt: Buffer.from(record.salt, 'base64'),
  })
  try {
    return await encryption.decrypt(record.data)
  } catch (cause) {
    throw new Error(`unable to decrypt DUST wallet state at ${dustStatePath}`, { cause })
  }
}

async function writeDustState(serialized) {
  const encryption = await StorageEncryption.create(privateStatePassword())
  const record = JSON.stringify({
    version: 1,
    salt: encryption.getSalt().toString('base64'),
    data: await encryption.encrypt(serialized),
  })
  mkdirSync(dirname(dustStatePath), { recursive: true })
  const temporaryPath = `${dustStatePath}.tmp-${process.pid}`
  writeFileSync(temporaryPath, `${record}\n`, { mode: 0o600 })
  renameSync(temporaryPath, dustStatePath)
}

function privateState() {
  const policyJson = process.env.DEPLOYSEAL_PRIVATE_POLICY_JSON || process.env.DEPLOYSEAL_POLICY_JSON
  const evidenceJson = process.env.DEPLOYSEAL_EVIDENCE_JSON
  if (!policyJson || !evidenceJson) throw new Error('DEPLOYSEAL_PRIVATE_POLICY_JSON/DEPLOYSEAL_EVIDENCE_JSON are required')
  const policy = JSON.parse(policyJson)
  const evidence = JSON.parse(evidenceJson)
  const salt = required('DEPLOYSEAL_PRIVATE_POLICY_SALT_HEX')
  if (!/^[0-9a-f]{64}$/u.test(salt)) throw new Error('DEPLOYSEAL_PRIVATE_POLICY_SALT_HEX must be 32-byte lowercase hex')
  return {
    policy: {
      criticalCves: BigInt(evidence.criticalCves),
      maxCriticalCves: BigInt(policy.maxCriticalCves),
      highCves: BigInt(evidence.highCves),
      maxHighCves: BigInt(policy.maxHighCves),
      evalScore: BigInt(evidence.evalScore),
      minEvalScore: BigInt(policy.minEvalScore),
      approvalCount: BigInt(new Set(evidence.approvalRoles).size),
      minimumApprovals: BigInt(policy.minimumApprovals),
    },
    salt: Buffer.from(salt, 'hex'),
  }
}

function persistentSubmissionService(config) {
  let apiPromise
  const getApi = async () => {
    if (!apiPromise) {
      apiPromise = ApiPromise.create({
        provider: new WsProvider(config.relayURL.toString()),
        throwOnConnect: true,
        noInitWarn: true,
      }).catch((error) => {
        apiPromise = undefined
        throw error
      })
    }
    const api = await apiPromise
    if (!api.isConnected) await api.connect()
    return api
  }
  return {
    async submitTransaction(transaction, waitForStatus = 'InBlock') {
      const api = await getApi()
      return new Promise((resolve, reject) => {
        let settled = false
        let unsubscribe
        const timeout = setTimeout(() => finish(reject, new Error('transaction submission timed out')), 120_000)
        const finish = (handler, value) => {
          if (settled) return
          settled = true
          clearTimeout(timeout)
          handler(value)
          if (unsubscribe) void unsubscribe()
        }
        api.tx.midnight
          .sendMnTransaction(`0x${Buffer.from(transaction.serialize()).toString('hex')}`)
          .send((result) => {
            const status = result.status
            if (status.isInvalid || status.isDropped || status.isUsurped || status.isFinalityTimeout) {
              finish(reject, new Error(`transaction rejected: ${status.type}`))
              return
            }
            const reached = waitForStatus === 'Submitted'
              ? status.isReady || status.isFuture || status.isBroadcast || status.isRetracted
              : waitForStatus === 'Finalized'
                ? status.isFinalized
                : status.isInBlock || status.isFinalized
            if (reached) finish(resolve, { status: status.type, txHash: result.txHash.toString() })
          })
          .then((stop) => {
            unsubscribe = stop
            if (settled) void unsubscribe()
          })
          .catch((error) => finish(reject, error))
      })
    },
    async close() {
      if (apiPromise) await (await apiPromise).disconnect()
    },
  }
}

function deriveKeys(seed) {
  const hd = HDWallet.fromSeed(Buffer.from(seed, 'hex'))
  if (hd.type !== 'seedOk') throw new Error('invalid Midnight wallet seed')
  const result = hd.hdWallet.selectAccount(0).selectRoles([Roles.Zswap, Roles.NightExternal, Roles.Dust]).deriveKeysAt(0)
  hd.hdWallet.clear()
  if (result.type !== 'keysDerived') throw new Error('unable to derive Midnight wallet keys')
  return result.keys
}

function intentSigner(tx, keystore, marker) {
  for (const segment of tx.intents?.keys() || []) {
    const intent = tx.intents.get(segment)
    if (!intent) continue
    const cloned = ledger.Intent.deserialize('signature', marker, 'pre-binding', intent.serialize())
    const signature = keystore.signData(cloned.signatureData(segment))
    if (cloned.fallibleUnshieldedOffer) cloned.fallibleUnshieldedOffer = cloned.fallibleUnshieldedOffer.addSignatures(cloned.fallibleUnshieldedOffer.inputs.map((_, index) => cloned.fallibleUnshieldedOffer.signatures.at(index) || signature))
    if (cloned.guaranteedUnshieldedOffer) cloned.guaranteedUnshieldedOffer = cloned.guaranteedUnshieldedOffer.addSignatures(cloned.guaranteedUnshieldedOffer.inputs.map((_, index) => cloned.guaranteedUnshieldedOffer.signatures.at(index) || signature))
    tx.intents.set(segment, cloned)
  }
}

async function ensureDust(context, { syncDust = true } = {}) {
  const unshieldedState = await context.wallet.unshielded.waitForSyncedState()
  if (syncDust && (await context.wallet.dust.waitForSyncedState()).balance(new Date()) > 0n) return null
  const nightUtxos = unshieldedState.availableCoins.filter((coin) => coin.meta?.registeredForDustGeneration !== true)
  if (nightUtxos.length === 0) {
    if (unshieldedState.availableCoins.length === 0) throw new Error('wallet has no tNIGHT to register for DUST generation')
    if (!syncDust) throw new Error('all available tNIGHT is already registered; use a persisted DUST state to inspect its balance')
    await Rx.firstValueFrom(
      context.wallet.dust.state().pipe(
        Rx.filter((value) => value.balance(new Date()) > 0n),
      ),
    )
    return
  }
  const recipe = await context.wallet.registerNightUtxosForDustGeneration(
    nightUtxos,
    context.unshieldedKeystore.getPublicKey(),
    (payload) => context.unshieldedKeystore.signData(payload),
  )
  const registrationTxId = await context.wallet.submitTransaction(await context.wallet.finalizeRecipe(recipe))
  if (syncDust) {
    await Rx.firstValueFrom(
      context.wallet.dust.state().pipe(
        Rx.filter((value) => value.balance(new Date()) > 0n),
      ),
    )
  }
  return registrationTxId
}

async function walletContext({ seedHex = required('DEPLOYSEAL_MIDNIGHT_SEED_HEX'), includeShielded = true, syncDust = true } = {}) {
  setNetworkId(network)
  const keys = deriveKeys(seedHex)
  const shieldedSecretKeys = ledger.ZswapSecretKeys.fromSeed(keys[Roles.Zswap])
  const dustSecretKey = ledger.DustSecretKey.fromSeed(keys[Roles.Dust])
  const unshieldedKeystore = createKeystore(keys[Roles.NightExternal], getNetworkId())
  const configuration = {
    networkId: getNetworkId(),
    indexerClientConnection: {
      indexerHttpUrl: endpoints.indexer,
      indexerWsUrl: endpoints.indexerWS,
      bufferSize: 2_000,
      resumeThreshold: 100,
    },
    batchUpdates: { size: 1_000, timeout: 1, spacing: 0 },
    provingServerUrl: new URL(endpoints.proof),
    relayURL: new URL(endpoints.node.replace(/^http/, 'ws')),
    txHistoryStorage: new InMemoryTransactionHistoryStorage(),
    costParameters: { additionalFeeOverhead: 300_000_000_000_000n, feeBlocksMargin: 5 },
  }
  const serializedDustState = syncDust ? await readDustState() : undefined
  const wallet = await WalletFacade.init({
    configuration,
    submissionService: (config) => persistentSubmissionService(config),
    shielded: (config) => ShieldedWallet(config).startWithSecretKeys(shieldedSecretKeys),
    unshielded: (config) => UnshieldedWallet(config).startWithPublicKey(PublicKey.fromKeyStore(unshieldedKeystore)),
    dust: (config) => serializedDustState
      ? DustWallet(config).restore(serializedDustState)
      : DustWallet(config).startWithSecretKey(dustSecretKey, ledger.LedgerParameters.initialParameters().dust),
  })
  const context = {
    wallet,
    shieldedSecretKeys,
    dustSecretKey,
    unshieldedKeystore,
    async stop() {
      try {
        if (syncDust) await writeDustState(await wallet.dust.serializeState())
      } finally {
        await wallet.stop()
      }
    },
  }
  await context.wallet.unshielded.start()
  if (syncDust) await context.wallet.dust.start(dustSecretKey)
  await context.wallet.pendingTransactionsService.start()
  if (syncDust) await ensureDust(context)
  if (includeShielded) await context.wallet.shielded.start(shieldedSecretKeys)
  return context
}

async function providers(context) {
  const state = await Rx.firstValueFrom(context.wallet.state().pipe(Rx.filter((value) => value.isSynced)))
  const accountId = state.shielded.coinPublicKey.toHexString()
  const password = privateStatePassword()
  const walletProvider = {
    getCoinPublicKey: () => state.shielded.coinPublicKey.toHexString(),
    getEncryptionPublicKey: () => state.shielded.encryptionPublicKey.toHexString(),
    async balanceTx(tx, ttl) {
      const recipe = await context.wallet.balanceUnboundTransaction(
        tx,
        { shieldedSecretKeys: context.shieldedSecretKeys, dustSecretKey: context.dustSecretKey },
        { ttl: ttl || new Date(Date.now() + 30 * 60 * 1000) },
      )
      intentSigner(recipe.baseTransaction, context.unshieldedKeystore, 'proof')
      if (recipe.balancingTransaction) intentSigner(recipe.balancingTransaction, context.unshieldedKeystore, 'pre-proof')
      return context.wallet.finalizeRecipe(recipe)
    },
    submitTx: (tx) => context.wallet.submitTransaction(tx),
  }
  return {
    privateStateProvider: levelPrivateStateProvider({
      midnightDbName: privateStateDb,
      privateStateStoreName: privateStateId,
      accountId,
      privateStoragePasswordProvider: () => password,
    }),
    publicDataProvider: indexerPublicDataProvider(endpoints.indexer, endpoints.indexerWS),
    zkConfigProvider: new NodeZkConfigProvider(zkConfigPath),
    proofProvider: httpClientProofProvider(endpoints.proof, new NodeZkConfigProvider(zkConfigPath)),
    walletProvider,
    midnightProvider: walletProvider,
  }
}

const compiled = CompiledContract.make('deployseal', DeploySeal.Contract).pipe(
  CompiledContract.withWitnesses(witnesses),
  CompiledContract.withCompiledFileAssets(zkConfigPath),
)

async function contractState(networkProviders, contractAddress) {
  const state = await networkProviders.publicDataProvider.queryContractState(contractAddress)
  if (!state) throw new Error('contract state not found')
  return DeploySeal.ledger(state.data)
}

function bytesEqual(left, right) {
  return Boolean(left) && Buffer.from(left).equals(Buffer.from(right))
}

function withTimeout(promise, message, timeoutMs = 120_000) {
  let timer
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), timeoutMs)
    }),
  ]).finally(() => clearTimeout(timer))
}

function decodeContractState(value) {
  const hex = typeof value === 'string' && value.startsWith('0x') ? value.slice(2) : value
  if (typeof hex !== 'string' || !/^[0-9a-f]+$/iu.test(hex)) return null
  try {
    return DeploySeal.ledger(ContractState.deserialize(Buffer.from(hex, 'hex')))
  } catch {
    return null
  }
}

async function latestContractTransaction(contractAddress, entryPoint, stateMatches) {
  const query = `
    query LatestContractAction($address: HexEncoded!) {
      contractAction(address: $address) {
        state
        ... on ContractCall {
          entryPoint
        }
        transaction {
          hash
          ... on RegularTransaction {
            identifiers
          }
        }
      }
    }
  `
  try {
    const response = await fetch(endpoints.indexer, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query, variables: { address: contractAddress } }),
      signal: AbortSignal.timeout(10_000),
    })
    if (!response.ok) return null
    const payload = await response.json()
    const action = payload?.data?.contractAction
    const transaction = action?.transaction
    if (payload?.errors || action?.entryPoint !== entryPoint || !stateMatches(decodeContractState(action.state))) return null
    if (typeof transaction?.hash !== 'string') return null
    return {
      txId: Array.isArray(transaction.identifiers) ? transaction.identifiers[0] || null : null,
      txHash: transaction.hash,
    }
  } catch {
    return null
  }
}

async function finalizedTransaction(publicDataProvider, txId) {
  if (!txId) return null
  try {
    return await withTimeout(publicDataProvider.watchForTxData(txId), 'Midnight transaction lookup timed out', 10_000)
  } catch {
    return null
  }
}

function requireReceipt(circuitId, transaction) {
  if (!transaction?.txHash) throw new Error(`Midnight ${circuitId} state changed but its transaction receipt could not be recovered`)
  return transaction
}

export async function createMidnightClient({
  contractAddress = required('DEPLOYSEAL_MIDNIGHT_CONTRACT_ADDRESS'),
  seedHex = required('DEPLOYSEAL_MIDNIGHT_SEED_HEX'),
} = {}) {
  const context = await walletContext({ seedHex })
  const networkProviders = await providers(context)
  await findDeployedContract(networkProviders, {
    contractAddress,
    compiledContract: compiled,
    privateStateId,
  })

  async function submitCircuit(circuitId, args) {
    const submitted = await submitCallTxAsync(networkProviders, {
      compiledContract: compiled,
      circuitId,
      contractAddress,
      privateStateId,
      args,
    })
    try {
      const finalized = await withTimeout(
        networkProviders.publicDataProvider.watchForTxData(submitted.txId),
        `Midnight ${circuitId} transaction finalization timed out`,
      )
      if (finalized.status !== SucceedEntirely) {
        throw Object.assign(new Error(`Midnight ${circuitId} transaction was not accepted`), { finalized })
      }
      await networkProviders.privateStateProvider.set(privateStateId, submitted.callTxData.private.nextPrivateState)
      return { txId: finalized.txId, txHash: finalized.txHash }
    } catch (cause) {
      throw Object.assign(cause instanceof Error ? cause : new Error(String(cause)), {
        submitted,
        finalized: cause?.finalized || cause?.finalizedTxData || null,
      })
    }
  }

  async function restoreSubmittedState(submitted) {
    const nextPrivateState = submitted?.callTxData?.private?.nextPrivateState
    if (nextPrivateState) await networkProviders.privateStateProvider.set(privateStateId, nextPrivateState)
  }

  async function reserve(core, expectedPolicyRoot) {
    const nullifier = operationNullifier(core)
    const before = await contractState(networkProviders, contractAddress)
    if (expectedPolicyRoot && Buffer.from(before.policyRoot).toString('hex') !== expectedPolicyRoot) {
      throw new Error('Midnight contract policy root does not match the configured policy')
    }
    if (before.operationNullifiers.member(nullifier)) {
      if (!bytesEqual(before.operationDigests.lookup(nullifier), Buffer.from(operationId(core), 'hex'))) {
        throw new Error('Midnight operation nullifier is bound to a different operation digest')
      }
      const recovered = requireReceipt('reserve', await latestContractTransaction(contractAddress, 'reserve', (state) => Boolean(
        state && state.operationNullifiers.member(nullifier) && bytesEqual(state.operationDigests.lookup(nullifier), Buffer.from(operationId(core), 'hex')),
      )))
      return {
        status: 'verified',
        kind: 'midnight-preprod',
        policyRoot: Buffer.from(before.policyRoot).toString('hex'),
        nullifier: nullifier.toString('hex'),
        operationId: operationId(core),
        txId: recovered?.txId || null,
        txHash: recovered?.txHash || null,
        recovered: true,
      }
    }
    try {
      const tx = await submitCircuit('reserve', [before.policyRoot, nullifier, Buffer.from(operationId(core), 'hex'), BigInt(core.policyEpoch)])
      return {
        status: 'verified',
        kind: 'midnight-preprod',
        policyRoot: Buffer.from(before.policyRoot).toString('hex'),
        nullifier: nullifier.toString('hex'),
        operationId: operationId(core),
        txId: tx.txId,
        txHash: tx.txHash,
      }
    } catch (cause) {
      const after = await contractState(networkProviders, contractAddress)
      if (!after.operationNullifiers.member(nullifier)) throw cause
      if (!bytesEqual(after.operationDigests.lookup(nullifier), Buffer.from(operationId(core), 'hex'))) {
        throw new Error('Midnight operation nullifier is bound to a different operation digest')
      }
      const finalized = await finalizedTransaction(networkProviders.publicDataProvider, cause.submitted?.txId)
      const recovered = requireReceipt('reserve', finalized || cause.finalized || await latestContractTransaction(contractAddress, 'reserve', (state) => Boolean(
        state && state.operationNullifiers.member(nullifier) && bytesEqual(state.operationDigests.lookup(nullifier), Buffer.from(operationId(core), 'hex')),
      )))
      await restoreSubmittedState(cause.submitted)
      return {
        status: 'verified',
        kind: 'midnight-preprod',
        policyRoot: Buffer.from(after.policyRoot).toString('hex'),
        nullifier: nullifier.toString('hex'),
        operationId: operationId(core),
        txId: recovered.txId || cause.finalized?.txId || null,
        txHash: recovered.txHash,
        recovered: true,
      }
    }
  }

  async function finalize(core, receiptHash, expectedPolicyRoot) {
    if (!/^[0-9a-f]{64}$/u.test(receiptHash)) throw new Error('receipt hash must be 32-byte lowercase hex')
    const nullifier = operationNullifier(core)
    const before = await contractState(networkProviders, contractAddress)
    if (expectedPolicyRoot && Buffer.from(before.policyRoot).toString('hex') !== expectedPolicyRoot) {
      throw new Error('Midnight contract policy root does not match the configured policy')
    }
    if (before.finalizedNullifiers.member(nullifier)) {
      if (!bytesEqual(before.receiptHashesByOperation.lookup(nullifier), Buffer.from(receiptHash, 'hex'))) {
        throw new Error('Midnight operation was finalized with a different receipt hash')
      }
      const recovered = requireReceipt('finalize', await latestContractTransaction(contractAddress, 'finalize', (state) => Boolean(
        state && state.finalizedNullifiers.member(nullifier) && bytesEqual(state.receiptHashesByOperation.lookup(nullifier), Buffer.from(receiptHash, 'hex')),
      )))
      return { status: 'verified', kind: 'midnight-preprod', operationId: operationId(core), txId: recovered.txId || null, txHash: recovered.txHash, recovered: true }
    }
    try {
      const tx = await submitCircuit('finalize', [nullifier, Buffer.from(receiptHash, 'hex')])
      return { status: 'verified', kind: 'midnight-preprod', operationId: operationId(core), txId: tx.txId, txHash: tx.txHash }
    } catch (cause) {
      const after = await contractState(networkProviders, contractAddress)
      if (!after.finalizedNullifiers.member(nullifier)) throw cause
      if (!bytesEqual(after.receiptHashesByOperation.lookup(nullifier), Buffer.from(receiptHash, 'hex'))) {
        throw new Error('Midnight operation was finalized with a different receipt hash')
      }
      const finalized = await finalizedTransaction(networkProviders.publicDataProvider, cause.submitted?.txId)
      const recovered = requireReceipt('finalize', finalized || cause.finalized || await latestContractTransaction(contractAddress, 'finalize', (state) => Boolean(
        state && state.finalizedNullifiers.member(nullifier) && bytesEqual(state.receiptHashesByOperation.lookup(nullifier), Buffer.from(receiptHash, 'hex')),
      )))
      await restoreSubmittedState(cause.submitted)
      return {
        status: 'verified',
        kind: 'midnight-preprod',
        operationId: operationId(core),
        txId: recovered.txId || cause.finalized?.txId || null,
        txHash: recovered.txHash,
        recovered: true,
      }
    }
  }

  return { reserve, finalize, close: () => context.stop() }
}

async function main() {
  const command = process.argv[2] || 'deploy'
  const context = await walletContext({ includeShielded: command !== 'dust', syncDust: command !== 'dust' })
  try {
    if (command === 'dust') {
      const registrationTxId = await ensureDust(context, { syncDust: false })
      const unshieldedState = await context.wallet.unshielded.waitForSyncedState()
      const tNight = unshieldedState.balances[ledger.unshieldedToken().raw] ?? 0n
      console.log(JSON.stringify({ network, address: context.unshieldedKeystore.getBech32Address().toString(), tNIGHT: tNight.toString(), dust: 'generating', registrationTxId }))
      return
    }
    const networkProviders = await providers(context)
    if (command === 'deploy') {
      const initialPrivateState = privateState()
      const deployed = await deployContract(networkProviders, {
        compiledContract: compiled,
        privateStateId,
        initialPrivateState,
      })
      console.log(JSON.stringify({ network, contractAddress: deployed.deployTxData.public.contractAddress, txId: deployed.deployTxData.public.txId, txHash: deployed.deployTxData.public.txHash }))
      return
    }
    const contractAddress = required('DEPLOYSEAL_MIDNIGHT_CONTRACT_ADDRESS')
    const deployed = await findDeployedContract(networkProviders, {
      contractAddress,
      compiledContract: compiled,
      privateStateId,
    })
    const core = JSON.parse(required('DEPLOYSEAL_OPERATION_CORE_JSON'))
    const nullifier = operationNullifier(core)
    if (command === 'reserve') {
      const state = await contractState(networkProviders, contractAddress)
      if (state.operationNullifiers.member(nullifier)) {
        if (!bytesEqual(state.operationDigests.lookup(nullifier), Buffer.from(operationId(core), 'hex'))) {
          throw new Error('operation nullifier is bound to a different operation digest')
        }
        const recovered = requireReceipt('reserve', await latestContractTransaction(contractAddress, 'reserve', (current) => Boolean(
          current && current.operationNullifiers.member(nullifier) && bytesEqual(current.operationDigests.lookup(nullifier), Buffer.from(operationId(core), 'hex')),
        )))
        console.log(JSON.stringify({ network, contractAddress, operationId: operationId(core), txId: recovered.txId, txHash: recovered.txHash, circuit: 'reserve', recovered: true }))
        return
      }
      const root = state.policyRoot
      const tx = await deployed.callTx.reserve(root, nullifier, Buffer.from(operationId(core), 'hex'), BigInt(core.policyEpoch))
      console.log(JSON.stringify({ network, contractAddress, operationId: operationId(core), txId: tx.public.txId, txHash: tx.public.txHash, circuit: 'reserve' }))
      return
    }
    if (command === 'finalize') {
      const receiptHashHex = required('DEPLOYSEAL_RECEIPT_HASH_HEX')
      if (!/^[0-9a-f]{64}$/u.test(receiptHashHex)) throw new Error('DEPLOYSEAL_RECEIPT_HASH_HEX must be 32-byte lowercase hex')
      const receiptHash = Buffer.from(receiptHashHex, 'hex')
      const state = await contractState(networkProviders, contractAddress)
      if (state.finalizedNullifiers.member(nullifier)) {
        if (!bytesEqual(state.receiptHashesByOperation.lookup(nullifier), receiptHash)) throw new Error('operation was finalized with a different receipt hash')
        const recovered = requireReceipt('finalize', await latestContractTransaction(contractAddress, 'finalize', (current) => Boolean(
          current && current.finalizedNullifiers.member(nullifier) && bytesEqual(current.receiptHashesByOperation.lookup(nullifier), receiptHash),
        )))
        console.log(JSON.stringify({ network, contractAddress, operationId: operationId(core), txId: recovered.txId, txHash: recovered.txHash, circuit: 'finalize', recovered: true }))
        return
      }
      const tx = await deployed.callTx.finalize(nullifier, receiptHash)
      console.log(JSON.stringify({ network, contractAddress, txId: tx.public.txId, txHash: tx.public.txHash, circuit: 'finalize' }))
      return
    }
    throw new Error(`unknown command: ${command}`)
  } finally {
    await context.stop()
  }
}

if (process.argv[1] === new URL(import.meta.url).pathname) await main()
