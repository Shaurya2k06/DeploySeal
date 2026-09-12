import { readFileSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import { KMSClient, VerifyCommand } from '@aws-sdk/client-kms'
import { AzureKeyVaultReceiptSigner } from './azure.js'
import { receiptBundleFromState, verifyReceiptBundle } from './receipt.js'

const inputPath = process.argv[2]
if (!inputPath) {
  console.error('usage: node src/verify-receipt.js <receipt-bundle-or-state.json>')
  process.exitCode = 2
} else {
  try {
    let input
    if (inputPath.endsWith('.sqlite')) {
      const database = new DatabaseSync(inputPath)
      try {
        input = JSON.parse(database.prepare('SELECT payload FROM deployseal_state WHERE id = 1').get()?.payload || 'null')
      } finally {
        database.close()
      }
    } else {
      input = JSON.parse(readFileSync(inputPath, 'utf8'))
    }
    const bundle = input.operations ? receiptBundleFromState(input) : input
    if (!bundle) throw new Error('no receipt found')
    const externalVerify = bundle.publicKey
      ? null
      : process.env.DEPLOYSEAL_PROVIDER === 'azure-arm'
        ? async (message, signature) => {
            const signer = new AzureKeyVaultReceiptSigner()
            return signer.verify(message, signature)
          }
      : async (message, signature) => {
          if (!process.env.AWS_REGION) throw new Error('AWS_REGION is required for KMS verification')
          const client = new KMSClient({ region: process.env.AWS_REGION })
          const result = await client.send(
            new VerifyCommand({
              KeyId: bundle.keyId,
              Message: message,
              MessageType: 'RAW',
              Signature: signature,
              SigningAlgorithm: process.env.DEPLOYSEAL_KMS_SIGNING_ALGORITHM || 'RSASSA_PSS_SHA_256',
            }),
          )
          return result.SignatureValid === true
        }
    const result = await verifyReceiptBundle(bundle, { kmsVerify: externalVerify })
    console.log(JSON.stringify(result, null, 2))
    if (!result.valid) process.exitCode = 1
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
