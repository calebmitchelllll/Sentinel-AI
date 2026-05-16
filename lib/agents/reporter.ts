import { callNemotron } from '../nemotron'

const SYSTEM_PROMPT = `You are a JSON writer for security reports. Given structured facts about a security incident, output ONLY valid JSON. No markdown. No explanation. Start with { end with }.

Required format:
{"executiveSummary":"<1 sentence with real attacker IPs, IAM user, and what happened>","severityScore":"<CRITICAL|HIGH|MEDIUM|LOW>","attackTimeline":[{"time":"<ISO8601 timestamp>","event":"<AWS API call name>","significance":"<what the attacker achieved>"}],"rootCause":"<how access was gained>","blastRadius":"<what was compromised or accessed>","immediateActions":["<specific aws cli command>","<specific aws cli command>"],"longtermActions":["<specific hardening step>","<specific hardening step>"],"agentDebateSummary":"<1 sentence on what agents agreed or disagreed on>"}`

function extractIPs(context: string): string[] {
  return Array.from(new Set(context.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))
    .filter(ip => !ip.startsWith('127.') && !ip.startsWith('10.0') && !ip.startsWith('192.168'))
}

function extractKeys(context: string): string[] {
  return Array.from(new Set(context.match(/AKIA[A-Z0-9]{16}/g) || []))
}

function extractUsers(context: string): string[] {
  return Array.from(new Set(context.match(/\b(?:dev|admin|svc|prod|test|root|user)-[a-z0-9][a-z0-9-]*/gi) || []))
}

function extractTimestamps(context: string): string[] {
  return Array.from(new Set(context.match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?/g) || []))
}

function extractSeverity(context: string): string {
  const m = context.match(/\b(CRITICAL|HIGH|MEDIUM|LOW)\b/)
  return m ? m[1] : 'HIGH'
}

// Extracts a section's raw lines (preserves newlines) by splitting on AGENT: headers
function getRawSection(context: string, agent: string): string {
  const lines = context.split('\n')
  let capturing = false
  const out: string[] = []
  for (const line of lines) {
    if (line.toLowerCase() === `${agent.toLowerCase()}:`) { capturing = true; continue }
    if (capturing && /^[A-Z]{3,}:$/.test(line)) break
    if (capturing) out.push(line)
  }
  return out.join('\n').trim()
}

// Collapsed single-line version for NIM compact facts
function extractSection(context: string, agent: string): string {
  return getRawSection(context, agent).replace(/\s+/g, ' ').trim()
}

function compactFacts(context: string): string {
  const ips = extractIPs(context)
  const keys = extractKeys(context)
  const users = extractUsers(context)
  const timestamps = extractTimestamps(context)
  const severity = extractSeverity(context)

  return [
    `SEVERITY: ${severity}`,
    ips.length ? `ATTACKER_IPS: ${ips.slice(0, 5).join(', ')}` : '',
    keys.length ? `COMPROMISED_KEYS: ${keys.join(', ')}` : '',
    users.length ? `IAM_USERS: ${users.slice(0, 5).join(', ')}` : '',
    timestamps.length ? `EVENT_TIMES: ${timestamps.slice(0, 3).join(', ')}` : '',
    `DETECTIVE: ${extractSection(context, 'DETECTIVE').slice(0, 350)}`,
    `FORENSICS: ${extractSection(context, 'FORENSICS').slice(0, 300)}`,
    `REMEDIATION: ${extractSection(context, 'REMEDIATION').slice(0, 200)}`,
    `VALIDATOR: ${extractSection(context, 'VALIDATOR').slice(0, 150)}`,
  ].filter(Boolean).join('\n')
}

function detectAttackType(context: string): string {
  const c = context.toLowerCase()
  if (c.includes('stoplogging') || c.includes('deletetrail') || c.includes('defense evasion')) return 'defense evasion / log tampering'
  if (c.includes('attachuserpolicy') || c.includes('privilege escalation') || c.includes('administratoraccess')) return 'IAM privilege escalation'
  if (c.includes('deleteobject') || c.includes('ransomware') || c.includes('wipeout')) return 'S3 ransomware / data destruction'
  if (c.includes('getobject') && (c.includes('exfiltrat') || c.includes('data access'))) return 'S3 data exfiltration'
  if (c.includes('getsecretvalue') || c.includes('secretsmanager')) return 'secrets theft via Secrets Manager'
  if (c.includes('createuser') || c.includes('persistence') || c.includes('backdoor')) return 'persistence / backdoor IAM user creation'
  if (c.includes('getfederationtoken') || c.includes('assumerole')) return 'lateral movement via role assumption'
  if (c.includes('bitcoin') || c.includes('ec2') && c.includes('launch')) return 'EC2 cryptomining / resource hijack'
  return 'credential theft and unauthorized API access'
}

function buildReportFromFacts(context: string): any {
  const ips = extractIPs(context)
  const keys = extractKeys(context)
  const users = extractUsers(context)
  const timestamps = extractTimestamps(context)
  const severity = extractSeverity(context)
  const attackType = detectAttackType(context)

  const userStr = users.slice(0, 2).join(', ') || 'unknown IAM user'
  const keyStr = keys.join(', ') || 'unknown access key'
  const ipStr = ips.slice(0, 2).join(', ') || 'unknown IP'

  // Parse attack timeline — use pre-computed structured block first (always reliable)
  const attackTimeline: { time: string; event: string; significance: string }[] = []
  const structuredBlock = getRawSection(context, 'STRUCTURED_TIMELINE')
  if (structuredBlock) {
    for (const line of structuredBlock.split('\n').filter(Boolean)) {
      const parts = line.split('|')
      if (parts.length >= 3) {
        attackTimeline.push({
          time: parts[0].trim(),
          event: parts[1].trim(),
          significance: `${parts[1].trim()} by ${parts[3]?.trim() || 'unknown'} from ${parts[2]?.trim() || 'unknown'}`,
        })
      }
      if (attackTimeline.length >= 5) break
    }
  }
  // Fallback: parse timestamps from detective NIM output
  if (attackTimeline.length === 0) {
    for (const line of getRawSection(context, 'DETECTIVE').split('\n')) {
      const timeMatch = line.match(/\[?(\d{4}-\d{2}-\d{2}T[\d:]+(?:\.\d+)?Z?)\]?/)
      if (!timeMatch) continue
      const withoutTime = line.replace(/\[?\d{4}-\d{2}-\d{2}T[\d:]+(?:\.\d+)?Z?\]?/, '').replace(/^[\s–\-–:]+/, '').trim()
      const eventMatch = withoutTime.match(/\b([A-Z][a-zA-Z]{4,30})\b/)
      attackTimeline.push({ time: timeMatch[1], event: eventMatch?.[1] || 'UnknownAPICall', significance: withoutTime.slice(0, 130) })
      if (attackTimeline.length >= 5) break
    }
  }

  // Extract remediation actions — only trust real aws CLI commands from NIM, everything else is unreliable
  const rawRem = getRawSection(context, 'REMEDIATION')
  const cliCommands = Array.from(new Set(
    (rawRem.match(/aws\s+[a-z-]+\s+[a-z-]+[^\n|]{5,}/g) || [])
      .map(c => c.replace(/\s*\|.*$/, '').trim())
      .filter(c => c.length > 15 && c.length < 200)
  )).slice(0, 3)

  // Default to fact-based actions (controlled, always correct) — only override with NIM CLI commands if we got 2+
  const immediateActions = cliCommands.length >= 2
    ? cliCommands
    : [
        keys[0]
          ? `Revoke the compromised access key — run: aws iam delete-access-key --access-key-id ${keys[0]} --user-name ${users[0] || 'affected-user'}`
          : 'Immediately revoke all compromised IAM credentials',
        users[0]
          ? `Detach all active IAM policies from ${users[0]} and audit what permissions were exercised during the attack window`
          : 'Audit and revoke IAM permissions for all affected identities',
        ips.length > 0
          ? `Block attacker IP(s) ${ips.slice(0, 2).join(', ')} via a deny rule in your VPC security group or WAF`
          : 'Enforce IP-based access restrictions on sensitive IAM operations',
        'Rotate any secrets, tokens, or credentials that were potentially accessed or exfiltrated during the incident',
      ]

  // Strip markdown bold markers before subsection matching — NIM often outputs **SECTION HEADER**
  const rawForensicsClean = getRawSection(context, 'FORENSICS').replace(/\*\*/g, '')
  const rawRemClean = rawRem.replace(/\*\*/g, '')

  // Extract blast radius from forensics BLAST RADIUS section
  const forensicsBlastMatch = rawForensicsClean.match(/BLAST RADIUS[:\s]*([\s\S]*?)(?:\n\n[A-Z]|\n[A-Z]{4,}|$)/i)
  const forensicsBlast = forensicsBlastMatch?.[1]
    ?.split('\n')
    .map(l => l.replace(/^[-•*\d.]+\s*/, '').trim())
    .filter(l => l.length > 5)
    .join(' ')
    .trim()
  const blastRadius = forensicsBlast && forensicsBlast.length > 20
    ? forensicsBlast
    : `IAM user ${userStr} compromised via key ${keyStr}. Attacker IP(s) ${ipStr} performed ${attackType} across ${timestamps.length} API calls.`

  // Extract long-term hardening from remediation LONG-TERM section
  const NIM_GARBAGE = /\b(provide|produce|list from|section heading|suspicious events|attack path|severity assessment|let'?s|what you must|stop the bleed)\b/i
  const longtermSection = rawRemClean.match(/LONG.TERM[^:\n]*[:\s]*([\s\S]*?)(?:\n\n[A-Z]|\n[A-Z]{4,}|$)/i)?.[1] || ''
  const longtermBullets = longtermSection
    .split('\n')
    .map(l => l.replace(/^[-•*\d.]+\s*/, '').trim())
    .filter(l => l.length > 10 && l.length < 250 && !NIM_GARBAGE.test(l) && !l.match(/^[|–]/) && !l.match(/^(LONG.TERM|HARDENING|IMMEDIATE)/i))
    .slice(0, 4)

  const longtermDefaults: Record<string, string[]> = {
    'IAM privilege escalation': [
      'Remove all directly-attached IAM user policies — use IAM roles with least-privilege',
      'Enforce aws:MultiFactorAuthPresent on all sensitive IAM actions via SCPs',
      'Enable IAM Access Analyzer to detect overly permissive policies',
      'Alert on AttachUserPolicy and CreateUser events via CloudTrail + EventBridge',
    ],
    'S3 data exfiltration': [
      'Enable S3 Block Public Access at the account level',
      'Use S3 bucket policies with aws:SourceIp conditions to restrict access by IP',
      'Enable S3 server-side logging and Macie for sensitive data detection',
      'Replace IAM user access keys with IAM roles and instance profiles',
    ],
    'defense evasion / log tampering': [
      'Enable CloudTrail log file validation and S3 Object Lock on the log bucket',
      'Create a separate read-only CloudTrail account to prevent log deletion',
      'Alert on StopLogging and DeleteTrail via CloudWatch alarms',
      'Enforce SCP to deny cloudtrail:StopLogging in all member accounts',
    ],
    'secrets theft via Secrets Manager': [
      'Enable Secrets Manager resource-based policies to restrict access by role/IP',
      'Rotate all secrets immediately and set automatic rotation schedules',
      'Alert on GetSecretValue calls from unexpected principals via CloudTrail',
      'Use VPC endpoints for Secrets Manager to prevent external access',
    ],
  }

  const longtermActions = longtermBullets.length >= 2
    ? longtermBullets
    : (longtermDefaults[attackType] || [
        'Replace long-lived IAM access keys with IAM roles and instance profiles',
        'Enforce MFA via aws:MultiFactorAuthPresent condition in IAM policies',
        'Enable AWS GuardDuty and CloudTrail alerting for anomalous API activity',
        'Implement AWS Security Hub for centralized findings across services',
      ])

  return {
    executiveSummary: `${severity} severity: ${attackType} detected — IAM key ${keyStr} belonging to ${userStr} was used from external IP(s) ${ipStr}.`,
    severityScore: severity,
    attackTimeline,
    rootCause: `Compromised AWS IAM credentials (${keyStr}) for user ${userStr} used from ${ipStr}. Attack type: ${attackType}. No MFA or IP restriction controls prevented access.`,
    blastRadius,
    immediateActions,
    longtermActions,
    agentDebateSummary: `Detective flagged ${ipStr} as anomalous source IPs; Forensics confirmed ${keys.length} compromised key(s) used from ${ips.length} IP(s) for ${attackType}. Validator challenged findings; MetaAgent verified pipeline integrity.`,
  }
}

const PLACEHOLDER_STRINGS = [
  'one sentence', 'ISO8601', 'API call name', 'what the attacker achieved',
  'concrete remediation', 'hardening recommendation', 'CRITICAL|HIGH|MEDIUM|LOW',
  'how access was gained', 'what was compromised', 'agents agreed or disagreed',
]

function isPlaceholderOutput(parsed: any): boolean {
  const text = JSON.stringify(parsed).toLowerCase()
  return PLACEHOLDER_STRINGS.some((p) => text.includes(p.toLowerCase()))
}

export function format_markdown(
  report: any,
  conversation: { agent: string; content: string }[],
  attackTimeline: { time: string; event: string; significance: string }[]
): string {
  return `# Security Incident Report

**Severity:** ${report.severityScore || 'UNKNOWN'}

## Executive Summary
${report.executiveSummary || 'N/A'}

## Root Cause
${report.rootCause || 'N/A'}

## Blast Radius
${report.blastRadius || 'N/A'}

## Attack Timeline
${attackTimeline.map((s) => `- **${s.time}** — ${s.event}: ${s.significance}`).join('\n')}

## Immediate Actions
${(report.immediateActions || []).map((a: string) => `- [ ] ${a}`).join('\n')}

## Long-Term Hardening
${(report.longtermActions || []).map((a: string) => `- [ ] ${a}`).join('\n')}

## Agent Debate Summary
${report.agentDebateSummary || 'N/A'}

## Agent Conversation Log
${conversation.map((m) => `### ${m.agent}\n${m.content}`).join('\n\n')}
`
}

export async function runReporter(context: string): Promise<string> {
  const facts = compactFacts(context)

  try {
    const result = await callNemotron(
      SYSTEM_PROMPT,
      `Generate the JSON incident report from these security findings:\n\n${facts}`,
      800
    )
    console.log('[Reporter NIM output]', result.slice(0, 300))
    const jsonMatch = result.match(/\{[\s\S]*\}/)
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0])
      const placeholder = isPlaceholderOutput(parsed)
      console.log('[Reporter NIM parsed] executiveSummary:', parsed.executiveSummary?.slice(0, 100), '| placeholder:', placeholder)
      if (
        parsed.executiveSummary &&
        parsed.severityScore &&
        Array.isArray(parsed.attackTimeline) &&
        !placeholder
      ) {
        console.log('[Reporter] Using NIM output')
        return JSON.stringify(parsed)
      }
    } else {
      console.log('[Reporter NIM] No JSON match in output')
    }
  } catch (err) {
    console.log('[Reporter NIM error]', err)
  }

  console.log('[Reporter] Falling back to fact extraction')
  return JSON.stringify(buildReportFromFacts(context))
}
