import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { DeploySealBroker } from '../src/broker.js'
import { receiptBundleFromState, verifyReceiptBundle } from '../src/receipt.js'
import { testBrokerOptions, testReceiptSigner } from './support.js'

test('receipt bundle verifies independently and rejects mutation', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'deployseal-receipt-'))
  const statePath = join(directory, 'state.json')
  try {
    const signer = testReceiptSigner()
    const broker = new DeploySealBroker(testBrokerOptions(statePath, { receiptSigner: signer }))
    await broker.start({ scenario: 'happy' })
    const bundle = receiptBundleFromState(JSON.parse(readFileSync(statePath, 'utf8')))
    assert.equal((await verifyReceiptBundle(bundle, { kmsVerify: (message, signature) => signer.verify(message, signature) })).valid, true)
    const mutated = { ...bundle, receipt: { ...bundle.receipt, actualTarget: 'other-stack' } }
    assert.equal((await verifyReceiptBundle(mutated, { kmsVerify: (message, signature) => signer.verify(message, signature) })).valid, false)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('receipt verifier reads the durable SQLite state', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'deployseal-receipt-sqlite-'))
  const statePath = join(directory, 'state.sqlite')
  try {
    const broker = new DeploySealBroker(testBrokerOptions(statePath))
    await broker.start({ scenario: 'happy' })
    assert.equal((await broker.verifyReceipt()).valid, true)
    broker.close()
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})
