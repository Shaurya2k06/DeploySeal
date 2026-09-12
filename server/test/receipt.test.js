import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { test } from 'node:test'
import { DeploySealBroker } from '../src/broker.js'
import { receiptBundleFromState, verifyReceiptBundle } from '../src/receipt.js'

const run = promisify(execFile)

test('receipt bundle verifies independently and rejects mutation', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'deployseal-receipt-'))
  const statePath = join(directory, 'state.json')
  try {
    const broker = new DeploySealBroker({ statePath })
    await broker.start({ scenario: 'happy' })
    const bundle = receiptBundleFromState(JSON.parse(readFileSync(statePath, 'utf8')))
    assert.equal((await verifyReceiptBundle(bundle)).valid, true)
    const mutated = { ...bundle, receipt: { ...bundle.receipt, actualTarget: 'other-stack' } }
    assert.equal((await verifyReceiptBundle(mutated)).valid, false)

    const { stdout } = await run(process.execPath, ['src/verify-receipt.js', statePath], {
      cwd: new URL('..', import.meta.url),
    })
    assert.match(stdout, /"valid": true/u)
    assert.doesNotMatch(stdout, /privateKey/u)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})
