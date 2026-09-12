import { createHash } from 'node:crypto'
import {
  CloudFormationClient,
  DescribeChangeSetCommand,
  ExecuteChangeSetCommand,
} from '@aws-sdk/client-cloudformation'
import { CloudTrailClient, LookupEventsCommand } from '@aws-sdk/client-cloudtrail'
import { KMSClient, SignCommand, VerifyCommand } from '@aws-sdk/client-kms'

const OPERATION_TOKEN = /^[A-Za-z0-9][-A-Za-z0-9]*$/u
const EXECUTION_STATUS = Object.freeze({
  EXECUTE_COMPLETE: 'SUCCEEDED',
  EXECUTE_FAILED: 'FAILED',
  FAILED: 'FAILED',
  OBSOLETE: 'FAILED',
  DELETE_COMPLETE: 'FAILED',
})

export const AWS_CLOUDFORMATION_CAPABILITIES = Object.freeze({
  nativeIdempotency: true,
  durableQueryByOperationId: true,
  receiptCanBindActualTargetAndDigest: true,
})

function error(code, message) {
  return Object.assign(new Error(message), { code })
}

export function assertProviderToken(token) {
  if (typeof token !== 'string' || token.length < 1 || token.length > 128 || !OPERATION_TOKEN.test(token)) {
    throw error('INVALID_PROVIDER_TOKEN', 'operation id is not a valid CloudFormation client token')
  }
}

function asIso(value, now) {
  return value ? new Date(value).toISOString() : new Date(now()).toISOString()
}

function isNotFound(cause) {
  return ['ChangeSetNotFound', 'ValidationError', 'ResourceNotFoundException'].includes(cause?.name || cause?.code)
}

export class AwsCloudFormationProvider {
  constructor({
    region = process.env.AWS_REGION,
    stackName = process.env.DEPLOYSEAL_CF_STACK,
    changeSetName = process.env.DEPLOYSEAL_CF_CHANGE_SET,
    artifactParameterKey = process.env.DEPLOYSEAL_CF_ARTIFACT_PARAMETER || 'DeploySealArtifactDigest',
    client = new CloudFormationClient({ region }),
    cloudTrailClient = new CloudTrailClient({ region }),
    now = Date.now,
  } = {}) {
    if (!region || !stackName || !changeSetName) {
      throw error('AWS_PROVIDER_CONFIG', 'AWS_REGION, DEPLOYSEAL_CF_STACK, and DEPLOYSEAL_CF_CHANGE_SET are required')
    }
    this.id = process.env.DEPLOYSEAL_PROVIDER_ID || 'aws-cloudformation'
    this.region = region
    this.stackName = stackName
    this.changeSetName = changeSetName
    this.artifactParameterKey = artifactParameterKey
    this.client = client
    this.cloudTrailClient = cloudTrailClient
    this.now = now
    this.capabilities = AWS_CLOUDFORMATION_CAPABILITIES
  }

  assertOperation(operationId, operation) {
    assertProviderToken(operationId)
    if (operation?.core?.targetId !== this.stackName) {
      throw error('PROVIDER_TARGET_MISMATCH', 'operation target does not match configured CloudFormation stack')
    }
  }

  async execute({ operationId, operation }) {
    this.assertOperation(operationId, operation)
    let response
    try {
      response = await this.client.send(
        new ExecuteChangeSetCommand({
          StackName: this.stackName,
          ChangeSetName: this.changeSetName,
          ClientRequestToken: operationId,
        }),
      )
    } catch (cause) {
      throw Object.assign(cause, { retryable: true })
    }

    return {
      operationId,
      providerOperationId: response.StackId || response.Id || this.changeSetName,
      actualTarget: this.stackName,
      actualArtifactDigest: operation.core.artifactDigest,
      status: 'PENDING',
      acceptedAt: asIso(undefined, this.now),
    }
  }

  async query({ operationId, operation }) {
    this.assertOperation(operationId, operation)
    let changeSet
    try {
      changeSet = await this.client.send(
        new DescribeChangeSetCommand({ StackName: this.stackName, ChangeSetName: this.changeSetName }),
      )
    } catch (cause) {
      if (isNotFound(cause)) return null
      throw cause
    }

    const parameter = changeSet.Parameters?.find(({ ParameterKey }) => ParameterKey === this.artifactParameterKey)
    const actualArtifactDigest = parameter?.ParameterValue?.replace(/^sha256:/u, '')
    const base = {
      operationId,
      providerOperationId: changeSet.StackId || changeSet.ChangeSetId || this.changeSetName,
      actualTarget: changeSet.StackName || this.stackName,
      actualArtifactDigest,
      status: EXECUTION_STATUS[changeSet.ExecutionStatus] || 'PENDING',
      completedAt: asIso(changeSet.LastUpdatedTime || changeSet.CreationTime, this.now),
    }
    if (base.status === 'PENDING') return base

    const cloudTrail = await this.findCloudTrailEvent(operationId)
    if (!cloudTrail) return { ...base, status: 'PENDING' }
    return {
      ...base,
      completedAt: asIso(cloudTrail.time || base.completedAt, this.now),
      cloudTrailEventHash: cloudTrail.hash,
      cloudTrailEventId: cloudTrail.id,
    }
  }

  async findCloudTrailEvent(operationId) {
    let nextToken
    for (let page = 0; page < 5; page += 1) {
      const response = await this.cloudTrailClient.send(
        new LookupEventsCommand({
          LookupAttributes: [{ AttributeKey: 'EventName', AttributeValue: 'ExecuteChangeSet' }],
          StartTime: new Date(this.now() - 24 * 60 * 60 * 1000),
          EndTime: new Date(this.now()),
          MaxResults: 50,
          ...(nextToken ? { NextToken: nextToken } : {}),
        }),
      )
      for (const event of response.Events || []) {
        if (!event.CloudTrailEvent) continue
        try {
          const detail = JSON.parse(event.CloudTrailEvent)
          if (detail.requestParameters?.clientRequestToken !== operationId) continue
          return {
            id: event.EventId || detail.eventID || null,
            hash: createHash('sha256').update(event.CloudTrailEvent).digest('hex'),
            time: event.EventTime || detail.eventTime || null,
          }
        } catch {
          // Ignore malformed unrelated events and keep looking.
        }
      }
      nextToken = response.NextToken
      if (!nextToken) break
    }
    return null
  }
}

export class AwsKmsReceiptSigner {
  constructor({
    region = process.env.AWS_REGION,
    keyId = process.env.DEPLOYSEAL_KMS_KEY_ID,
    signingAlgorithm = process.env.DEPLOYSEAL_KMS_SIGNING_ALGORITHM || 'RSASSA_PSS_SHA_256',
    client = new KMSClient({ region }),
  } = {}) {
    if (!region || !keyId) throw error('KMS_CONFIG', 'AWS_REGION and DEPLOYSEAL_KMS_KEY_ID are required')
    this.id = keyId
    this.signingAlgorithm = signingAlgorithm
    this.client = client
  }

  async sign(message) {
    const response = await this.client.send(
      new SignCommand({
        KeyId: this.id,
        Message: message,
        MessageType: 'RAW',
        SigningAlgorithm: this.signingAlgorithm,
      }),
    )
    if (!response.Signature) throw error('KMS_NO_SIGNATURE', 'KMS returned no receipt signature')
    return Buffer.from(response.Signature)
  }

  async verify(message, signature) {
    const response = await this.client.send(
      new VerifyCommand({
        KeyId: this.id,
        Message: message,
        MessageType: 'RAW',
        Signature: signature,
        SigningAlgorithm: this.signingAlgorithm,
      }),
    )
    return response.SignatureValid === true
  }
}
