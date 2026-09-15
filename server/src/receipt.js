import { verify as verifySignature } from 'node:crypto'
import { receiptHash } from './protocol.js'

export function receiptBundleFromState(state) {
  const operations = Object.values(state?.operations || {})
  const operation = operations.at(-1)
  if (!operation?.receipt || !operation.receiptHash || !operation.receiptSignature) return null
  return {
    receipt: operation.receipt,
    receiptHash: operation.receiptHash,
    signature: operation.receiptSignature,
    publicKey: null,
    keyId: operation.receipt.receiptKeyId,
  }
}

export async function verifyReceiptBundle(bundle, { kmsVerify = null } = {}) {
  if (!bundle?.receipt || typeof bundle.signature !== 'string') {
    return { valid: false, code: 'INVALID_RECEIPT_BUNDLE' }
  }
  const computedHash = receiptHash(bundle.receipt)
  const hashMatches = computedHash === bundle.receiptHash
  const signature = Buffer.from(bundle.signature, 'base64')
  const signatureValid = bundle.publicKey
    ? verifySignature(null, Buffer.from(computedHash, 'hex'), bundle.publicKey, signature)
    : kmsVerify
      ? await kmsVerify(Buffer.from(computedHash, 'hex'), signature)
      : false
  return {
    valid: hashMatches && signatureValid,
    hashMatches,
    signatureValid,
    receiptHash: bundle.receiptHash,
    keyId: bundle.keyId || bundle.receipt.receiptKeyId,
  }
}
