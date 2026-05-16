import { callNemotron } from '../nemotron'

const SYSTEM_PROMPT = `You are a cloud forensics analyst. Given AWS CloudTrail logs, determine: which credential was used, when the attacker first appeared, what services and data were accessed, and the full blast radius. Be precise. Output sections: STOLEN CREDENTIAL, FIRST CONTACT, DATA ACCESSED, BLAST RADIUS.`

function analyzeCredentials(events: any[]): string {
  // Group events by access key / identity
  const keyUsage: Record<string, { ips: Set<string>; events: string[] }> = {}

  for (const e of events) {
    const key = e.userIdentity?.accessKeyId || e.userIdentity?.principalId || 'unknown'
    if (!keyUsage[key]) keyUsage[key] = { ips: new Set(), events: [] }
    if (e.sourceIPAddress) keyUsage[key].ips.add(e.sourceIPAddress)
    keyUsage[key].events.push(e.eventName)
  }

  return Object.entries(keyUsage)
    .filter(([, v]) => v.ips.size > 1) // keys used from multiple IPs are suspicious
    .map(([key, v]) => `Key ${key}: used from ${v.ips.size} IPs [${[...v.ips].join(', ')}], ${v.events.length} total calls`)
    .join('\n') || 'Single IP per credential — check timeline for anomalies'
}

function extractDataAccess(events: any[]): string[] {
  const dataEvents = events.filter((e) =>
    ['GetObject', 'GetSecretValue', 'BatchGetSecretValue', 'GetParameter', 'GetParameters'].includes(e.eventName)
  )
  return dataEvents.map((e) => {
    if (e.eventName === 'GetObject') {
      return `S3: s3://${e.requestParameters?.bucketName}/${e.requestParameters?.key} at ${e.eventTime} from ${e.sourceIPAddress}`
    }
    if (e.eventName.includes('SecretValue')) {
      return `Secrets Manager: ${e.requestParameters?.secretId} at ${e.eventTime} from ${e.sourceIPAddress}`
    }
    return `${e.eventName}: ${JSON.stringify(e.requestParameters || {}).slice(0, 100)} at ${e.eventTime}`
  })
}

function extractDestructiveActions(events: any[]): string[] {
  const destructive = events.filter((e) =>
    ['DeleteObject', 'DeleteObjects', 'PutBucketPolicy', 'PutBucketVersioning',
      'StopLogging', 'DeleteTrail', 'PutEventSelectors', 'ModifyImageAttribute',
      'ModifySnapshotAttribute', 'CreateUser', 'CreateAccessKey', 'AttachUserPolicy'].includes(e.eventName)
  )
  return destructive.map(
    (e) => `${e.eventName} at ${e.eventTime} from ${e.sourceIPAddress}${e.errorCode ? ' [BLOCKED: ' + e.errorCode + ']' : ''}`
  )
}

export async function runForensics(cloudtrailEvents: any[]): Promise<string> {
  const credentialAnalysis = analyzeCredentials(cloudtrailEvents)
  const dataAccess = extractDataAccess(cloudtrailEvents)
  const destructiveActions = extractDestructiveActions(cloudtrailEvents)

  // Find first event from an IP not seen in the baseline
  const cutoff = Math.floor(cloudtrailEvents.length * 0.75)
  const baselineIPs = new Set(cloudtrailEvents.slice(0, cutoff).map((e) => e.sourceIPAddress))
  const firstAttackEvent = cloudtrailEvents.find((e) => !baselineIPs.has(e.sourceIPAddress))

  const context = `
Credential usage analysis (keys used from multiple IPs):
${credentialAnalysis}

First attacker contact: ${firstAttackEvent ? `${firstAttackEvent.eventTime} — ${firstAttackEvent.eventName} from ${firstAttackEvent.sourceIPAddress} as ${firstAttackEvent.userIdentity?.userName || firstAttackEvent.userIdentity?.type}` : 'Unknown'}

Data accessed (${dataAccess.length} events):
${dataAccess.join('\n') || 'None detected'}

Destructive / persistence actions (${destructiveActions.length} events):
${destructiveActions.join('\n') || 'None detected'}
`

  return callNemotron(SYSTEM_PROMPT, `Perform forensic analysis on this AWS incident:\n${context}`)
}
