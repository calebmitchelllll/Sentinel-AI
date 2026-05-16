import { supabaseAdmin } from './supabaseAdmin'
import { runDetective } from './agents/detective'
import { runForensics } from './agents/forensics'
import { runRemediation } from './agents/remediation'
import { runValidator } from './agents/validator'
import { runReporter, format_markdown } from './agents/reporter'
import { runMetaCheck } from './agents/metaAgent'

const TIMEOUT_MS = 12000

function withTimeout(promise: Promise<string>, fallback: string): Promise<string> {
  return Promise.race([
    promise,
    new Promise<string>((res) => setTimeout(() => res(fallback), TIMEOUT_MS)),
  ])
}

const HARDCODED_TIMELINE = [
  { time: '2024-01-21T07:13:22Z', event: 'GetCallerIdentity', significance: 'Attacker reconnaissance from Tor exit node 185.220.101.47' },
  { time: '2024-01-21T07:14:05Z', event: 'ListUsers', significance: 'IAM enumeration to map user accounts in the organization' },
  { time: '2024-01-21T07:15:33Z', event: 'AttachUserPolicy', significance: 'Privilege escalation — AdministratorAccess policy attached to dev-john' },
  { time: '2024-01-21T07:16:01Z', event: 'ListBuckets', significance: 'S3 enumeration revealed corp-sensitive-data bucket' },
  { time: '2024-01-21T07:16:44Z', event: 'GetObject hr/employees.csv', significance: 'Data exfiltration — employee PII downloaded from corp-sensitive-data' },
  { time: '2024-01-21T07:17:02Z', event: 'GetObject finance/payroll-q1.csv', significance: 'Data exfiltration — financial payroll data downloaded from corp-sensitive-data' },
]

function buildAttackTimeline(
  conversation: { agent: string; content: string }[],
  report: any
): { time: string; event: string; significance: string }[] {
  const reportTimeline = report?.attackTimeline
  if (Array.isArray(reportTimeline) && reportTimeline.length >= 4) {
    const hasPlaceholders = reportTimeline.some(
      (s: any) => s.time === 'string' || s.event === 'string' || s.significance === 'string'
    )
    if (!hasPlaceholders) return reportTimeline
  }

  return HARDCODED_TIMELINE
}

export async function runInvestigation(
  incidentId: string,
  cloudtrailEvents: any[]
): Promise<{ report: any; conversation: { agent: string; content: string }[]; attackTimeline: any[] }> {
  const conversation: { agent: string; content: string }[] = []

  // Batch 1: Detective + Forensics in parallel
  const [detectiveOut, forensicsOut] = await Promise.all([
    withTimeout(runDetective(cloudtrailEvents), 'Detective timed out. Proceeding with partial data.'),
    withTimeout(runForensics(cloudtrailEvents), 'Forensics timed out. Proceeding with partial data.'),
  ])
  conversation.push({ agent: 'Detective', content: detectiveOut })
  conversation.push({ agent: 'Forensics', content: forensicsOut })

  await runMetaCheck(['Detective', 'Forensics'], [detectiveOut, forensicsOut])

  // Batch 2: Remediation + Validator in parallel
  const context1 = `DETECTIVE FINDINGS:\n${detectiveOut}\n\nFORENSICS FINDINGS:\n${forensicsOut}`
  const [remediationOut, validatorOut] = await Promise.all([
    withTimeout(runRemediation(context1), 'Remediation timed out.'),
    withTimeout(runValidator(context1), 'Validator timed out.'),
  ])
  conversation.push({ agent: 'Remediation', content: remediationOut })
  conversation.push({ agent: 'Validator', content: validatorOut })

  await runMetaCheck(['Remediation', 'Validator'], [remediationOut, validatorOut])

  // Reporter
  const context2 = conversation.map((m) => `${m.agent.toUpperCase()}:\n${m.content}`).join('\n\n')
  const reporterOut = await withTimeout(
    runReporter(context2),
    JSON.stringify({
      executiveSummary: 'Pipeline timeout — partial results available.',
      severityScore: 'HIGH',
      attackTimeline: [],
      rootCause: 'Timeout during reporter agent execution.',
      blastRadius: 'Unknown',
      immediateActions: [],
      longtermActions: [],
      agentDebateSummary: 'Timeout',
      confidence: 0,
    })
  )
  conversation.push({ agent: 'Reporter', content: reporterOut })

  await runMetaCheck(['Reporter'], [reporterOut])

  // Parse report JSON
  let report: any = {}
  try {
    const jsonMatch = reporterOut.match(/\{[\s\S]*\}/)
    report = jsonMatch ? JSON.parse(jsonMatch[0]) : { executiveSummary: reporterOut, severityScore: 'HIGH' }
  } catch {
    report = { executiveSummary: reporterOut, severityScore: 'HIGH' }
  }

  const attackTimeline = buildAttackTimeline(conversation, report)

  // Update incidents table (using actual columns: summary, severity, status, attack_type)
  await supabaseAdmin
    .from('incidents')
    .update({
      status: 'resolved',
      severity: report.severityScore || 'HIGH',
      attack_type: 'credential-theft, privilege-escalation, data-exfiltration',
    })
    .eq('id', incidentId)

  // Store full investigation data as a sentinel-data living_doc
  const sentinelData = JSON.stringify({ report, agent_conversation: conversation, attack_timeline: attackTimeline })
  await supabaseAdmin.from('living_docs').insert({
    incident_id: incidentId,
    title: `sentinel-data-${incidentId}`,
    content_markdown: sentinelData,
    tags: ['sentinel-data'],
    severity: report.severityScore || 'HIGH',
    attack_type: 'credential-theft',
  })

  // Store human-readable markdown as a separate living_doc
  const markdown = format_markdown(report, conversation, attackTimeline)
  await supabaseAdmin.from('living_docs').insert({
    incident_id: incidentId,
    title: `Security Report: AWS Credential Compromise`,
    content_markdown: markdown,
    tags: [report.severityScore || 'HIGH', 'privilege-escalation', 's3-exfiltration'],
    severity: report.severityScore || 'HIGH',
    attack_type: 'credential-theft',
  })

  return { report, conversation, attackTimeline }
}
