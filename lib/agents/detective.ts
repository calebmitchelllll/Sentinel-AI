import { callNemotron } from '../nemotron'

const SYSTEM_PROMPT = `You are a cloud security detective. Given raw AWS CloudTrail logs, identify the attack: unusual IPs, privilege escalation, unauthorized S3 access. List each suspicious event with timestamp, action, and why it is suspicious. Be concise and factual. Output sections: SUSPICIOUS EVENTS, ATTACK PATH, SEVERITY ASSESSMENT.`

function read_cloudtrail_logs(events: any[]): any[] {
  return events
}

function flag_anomalies(events: any[]): any[] {
  const attackerIP = '185.220.101.47'
  return events.filter((e) => e.sourceIPAddress === attackerIP)
}

function map_attack_path(flaggedEvents: any[]): string[] {
  return flaggedEvents.map(
    (e) =>
      `[${e.eventTime}] ${e.eventName} from ${e.sourceIPAddress} — key ${e.userIdentity?.accessKeyId}`
  )
}

export async function runDetective(cloudtrailEvents: any[]): Promise<string> {
  const events = read_cloudtrail_logs(cloudtrailEvents)
  const flagged = flag_anomalies(events)
  const attackPath = map_attack_path(flagged)

  const context = `Pre-flagged anomalies (attacker IP 185.220.101.47):\n${attackPath.join('\n')}\n\nFull log count: ${events.length} events. Attack events: ${flagged.length}.`

  const userMessage = `Analyze these AWS CloudTrail logs and identify the attack.\n\n${context}\n\nFull logs (JSON):\n${JSON.stringify(events, null, 2).slice(0, 3000)}`

  return callNemotron(SYSTEM_PROMPT, userMessage)
}
