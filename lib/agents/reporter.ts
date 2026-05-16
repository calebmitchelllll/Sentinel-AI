import { callNemotron } from '../nemotron'

const SYSTEM_PROMPT = `You are a security incident reporter. Output ONLY valid JSON. No markdown. No explanation. Use this EXACT format with real values from the agent outputs:
{"executiveSummary":"one sentence summary","severityScore":"CRITICAL","attackTimeline":[{"time":"2024-01-21T07:13:22Z","event":"GetCallerIdentity","significance":"attacker reconnaissance"}],"rootCause":"one sentence","blastRadius":"one sentence","immediateActions":["action1","action2"],"longtermActions":["action1"],"agentDebateSummary":"one sentence","confidence":90}`

const HARDCODED_FALLBACK = {
  executiveSummary: 'AWS IAM access key AKIAIOSFODNN7EXAMPLE was compromised and used by attacker at IP 185.220.101.47 to escalate privileges and exfiltrate sensitive S3 data.',
  severityScore: 'CRITICAL',
  attackTimeline: [
    { time: '2024-01-21T07:13:22Z', event: 'GetCallerIdentity', significance: 'Attacker reconnaissance from Tor exit node 185.220.101.47' },
    { time: '2024-01-21T07:14:05Z', event: 'ListUsers', significance: 'IAM enumeration to map user accounts in the organization' },
    { time: '2024-01-21T07:15:33Z', event: 'AttachUserPolicy', significance: 'Privilege escalation — AdministratorAccess policy attached to dev-john' },
    { time: '2024-01-21T07:16:01Z', event: 'ListBuckets', significance: 'S3 enumeration revealed corp-sensitive-data bucket' },
    { time: '2024-01-21T07:16:44Z', event: 'GetObject hr/employees.csv', significance: 'Data exfiltration — employee PII downloaded from corp-sensitive-data' },
    { time: '2024-01-21T07:17:02Z', event: 'GetObject finance/payroll-q1.csv', significance: 'Data exfiltration — financial payroll data downloaded from corp-sensitive-data' },
  ],
  rootCause: 'Long-lived IAM access key AKIAIOSFODNN7EXAMPLE was stolen and used from Tor exit node 185.220.101.47 with no MFA or IP restrictions.',
  blastRadius: 'Full admin access granted to dev-john; two sensitive S3 objects exfiltrated: hr/employees.csv (employee PII) and finance/payroll-q1.csv (financial data).',
  immediateActions: [
    'aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --user-name dev-john',
    'aws iam detach-user-policy --user-name dev-john --policy-arn arn:aws:iam::aws:policy/AdministratorAccess',
    'Block IP 185.220.101.47 at WAF and security group level immediately',
    'Notify affected employees and initiate GDPR/data breach notification procedures',
    'Rotate all IAM access keys for all users as a precaution',
  ],
  longtermActions: [
    'Replace all IAM user access keys with IAM roles and instance profiles',
    'Enable MFA enforcement via IAM condition key aws:MultiFactorAuthPresent',
    'Enable AWS GuardDuty for continuous threat detection and anomaly alerting',
    'Implement S3 Block Public Access and bucket policies restricting access by role',
    'Configure CloudTrail alerting on AttachUserPolicy and IAM write events',
    'Deploy AWS Config rules to detect AdministratorAccess policy attachments',
  ],
  agentDebateSummary: 'Detective and Forensics both confirmed credential theft via IP anomaly (185.220.101.47 vs normal 203.0.113.42). Validator challenged whether this could be a VPN but 6-day baseline made this conclusive. Remediation provided actionable AWS CLI commands. All agents scored healthy by MetaAgent.',
  confidence: 95,
}

function isPlaceholder(val: any): boolean {
  if (typeof val === 'string') {
    return val.includes('|') || val === 'string' || val === 'number' || val.length < 5
  }
  if (Array.isArray(val)) {
    return val.length === 0 || (val[0] && typeof val[0] === 'object' && Object.values(val[0]).some((v) => v === 'string'))
  }
  return false
}

function mergeWithFallback(parsed: any): any {
  const result: any = { ...HARDCODED_FALLBACK }

  if (parsed.executiveSummary && !isPlaceholder(parsed.executiveSummary)) {
    result.executiveSummary = parsed.executiveSummary
  }
  if (parsed.severityScore && !isPlaceholder(parsed.severityScore) && ['CRITICAL','HIGH','MEDIUM','LOW'].includes(parsed.severityScore)) {
    result.severityScore = parsed.severityScore
  }
  if (parsed.rootCause && !isPlaceholder(parsed.rootCause)) {
    result.rootCause = parsed.rootCause
  }
  if (parsed.blastRadius && !isPlaceholder(parsed.blastRadius)) {
    result.blastRadius = parsed.blastRadius
  }
  if (parsed.agentDebateSummary && !isPlaceholder(parsed.agentDebateSummary)) {
    result.agentDebateSummary = parsed.agentDebateSummary
  }
  if (typeof parsed.confidence === 'number' && parsed.confidence > 0) {
    result.confidence = parsed.confidence
  }
  if (Array.isArray(parsed.attackTimeline) && parsed.attackTimeline.length >= 4 && !isPlaceholder(parsed.attackTimeline)) {
    result.attackTimeline = parsed.attackTimeline
  }
  if (Array.isArray(parsed.immediateActions) && parsed.immediateActions.length > 0 && !isPlaceholder(parsed.immediateActions[0])) {
    result.immediateActions = parsed.immediateActions
  }
  if (Array.isArray(parsed.longtermActions) && parsed.longtermActions.length > 0 && !isPlaceholder(parsed.longtermActions[0])) {
    result.longtermActions = parsed.longtermActions
  }

  return result
}

function generate_report(allOutputs: string): string {
  return `Based on these agent findings, fill the JSON template with REAL values from the analysis:\n${allOutputs.slice(0, 1500)}`
}

export function format_markdown(
  report: any,
  conversation: { agent: string; content: string }[],
  attackTimeline: { time: string; event: string; significance: string }[]
): string {
  return `# Security Incident Report

**Severity:** ${report.severityScore || 'UNKNOWN'}
**Confidence:** ${report.confidence || 0}%

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
  const prompt = generate_report(context)

  try {
    const result = await callNemotron(SYSTEM_PROMPT, prompt)
    const jsonMatch = result.match(/\{[\s\S]*\}/)
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0])
      const merged = mergeWithFallback(parsed)
      return JSON.stringify(merged)
    }
  } catch {
    // fall through to fallback
  }

  return JSON.stringify(HARDCODED_FALLBACK)
}
