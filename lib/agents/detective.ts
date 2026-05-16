import { callNemotron } from '../nemotron'

const SYSTEM_PROMPT = `You are a cloud security detective. Given AWS CloudTrail logs, identify the attack: unusual IPs, privilege escalation, data exfiltration, credential theft, defense evasion, or lateral movement. List each suspicious event with timestamp, action, and why it is suspicious. Output sections: SUSPICIOUS EVENTS, ATTACK PATH, SEVERITY ASSESSMENT.`

const HIGH_RISK_EVENTS = new Set([
  'CreateUser', 'CreateAccessKey', 'AttachUserPolicy', 'PutUserPolicy', 'DeleteUser',
  'PutBucketPolicy', 'DeleteBucketPolicy', 'PutBucketAcl', 'PutBucketVersioning',
  'StopLogging', 'DeleteTrail', 'PutEventSelectors',
  'GetSecretValue', 'BatchGetSecretValue', 'ListSecrets',
  'DeleteObject', 'DeleteObjects',
  'ModifyImageAttribute', 'ModifySnapshotAttribute',
  'AssumeRole', 'GetFederationToken',
])

function detectAttackerIPs(events: any[]): Set<string> {
  // IPs seen in the baseline (first 75% of events) are normal developer IPs
  const cutoff = Math.floor(events.length * 0.75)
  const baselineIPs = new Set(events.slice(0, cutoff).map((e) => e.sourceIPAddress).filter(Boolean))
  const recentIPs = new Set(events.slice(cutoff).map((e) => e.sourceIPAddress).filter(Boolean))

  const newIPs = new Set<string>()
  for (const ip of recentIPs) {
    if (!baselineIPs.has(ip)) newIPs.add(ip)
  }

  // Fallback: if no new IPs (e.g. attacker reuses same egress), flag IPs on high-risk events
  if (newIPs.size === 0) {
    events
      .filter((e) => HIGH_RISK_EVENTS.has(e.eventName))
      .forEach((e) => { if (e.sourceIPAddress) newIPs.add(e.sourceIPAddress) })
  }

  return newIPs
}

function flagAnomalies(events: any[]): any[] {
  const attackerIPs = detectAttackerIPs(events)
  return events.filter(
    (e) => attackerIPs.has(e.sourceIPAddress) || HIGH_RISK_EVENTS.has(e.eventName)
  )
}

function buildContext(events: any[], flagged: any[]): string {
  const uniqueIPs = [...new Set(flagged.map((e) => e.sourceIPAddress).filter(Boolean))]
  const uniqueUsers = [...new Set(flagged.map((e) => e.userIdentity?.userName || e.userIdentity?.type).filter(Boolean))]
  const eventTypes = [...new Set(flagged.map((e) => e.eventName))]

  const lines = flagged.map((e) => {
    const err = e.errorCode ? ` → BLOCKED: ${e.errorCode}` : ''
    const bytes = e.additionalEventData?.bytesTransferredOut
      ? ` (${(e.additionalEventData.bytesTransferredOut / 1024).toFixed(0)} KB out)`
      : ''
    return `[${e.eventTime}] ${e.eventName} on ${e.eventSource} from ${e.sourceIPAddress} as ${e.userIdentity?.userName || e.userIdentity?.type}${bytes}${err}`
  })

  return `Total log events: ${events.length} | Suspicious events flagged: ${flagged.length}
Anomalous source IPs: ${uniqueIPs.join(', ')}
Involved identities: ${uniqueUsers.join(', ')}
High-risk event types: ${eventTypes.join(', ')}

Flagged events (chronological):
${lines.join('\n')}`
}

export async function runDetective(cloudtrailEvents: any[]): Promise<string> {
  const flagged = flagAnomalies(cloudtrailEvents)
  const context = buildContext(cloudtrailEvents, flagged)
  return callNemotron(SYSTEM_PROMPT, `Analyze these AWS CloudTrail events and identify the attack:\n\n${context}`)
}
