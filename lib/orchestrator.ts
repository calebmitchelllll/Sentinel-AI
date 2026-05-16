import { supabaseAdmin } from './supabaseAdmin'
import { runDetective } from './agents/detective'
import { runForensics } from './agents/forensics'
import { runRemediation } from './agents/remediation'
import { runValidator } from './agents/validator'
import { runReporter, format_markdown } from './agents/reporter'
import { runMetaCheck, MetaResult } from './agents/metaAgent'

const AGENT_TIMEOUT_MS = 25000
const REPORTER_TIMEOUT_MS = 55000

const HIGH_RISK_EVENTS = new Set([
  'CreateUser', 'CreateAccessKey', 'AttachUserPolicy', 'PutUserPolicy', 'DeleteUser',
  'PutBucketPolicy', 'DeleteBucketPolicy', 'PutBucketAcl',
  'StopLogging', 'DeleteTrail', 'PutEventSelectors',
  'GetSecretValue', 'BatchGetSecretValue', 'ListSecrets',
  'DeleteObject', 'DeleteObjects', 'GetObject',
  'AssumeRole', 'GetFederationToken',
  'GetCallerIdentity', 'ListUsers', 'ListBuckets',
])

function buildAttackTimeline(events: any[]): { time: string; event: string; significance: string }[] {
  const cutoff = Math.floor(events.length * 0.75)
  const baselineIPs = new Set(events.slice(0, cutoff).map((e: any) => e.sourceIPAddress))

  const attackerEvents = events.filter((e: any) => !baselineIPs.has(e.sourceIPAddress))
  const candidates = attackerEvents.length > 0
    ? attackerEvents.slice(0, 8)
    : events.filter((e: any) => HIGH_RISK_EVENTS.has(e.eventName)).slice(0, 8)

  return candidates.map((e: any) => ({
    time: e.eventTime,
    event: e.eventName,
    significance: `${e.eventName} by ${e.userIdentity?.userName || e.userIdentity?.type || 'unknown'} from ${e.sourceIPAddress}`,
  }))
}

function buildStructuredTimelineString(events: any[]): string {
  return buildAttackTimeline(events)
    .map(e => `${e.time}|${e.event}|${e.significance}`)
    .join('\n')
}

function withTimeout(promise: Promise<string>, fallback: string, ms = AGENT_TIMEOUT_MS): Promise<string> {
  return Promise.race([
    promise,
    new Promise<string>((res) => setTimeout(() => res(fallback), ms)),
  ])
}

export async function runInvestigation(
  incidentId: string,
  cloudtrailEvents: any[],
  techniqueId: string
): Promise<{ report: any; conversation: { agent: string; content: string }[]; attackTimeline: any[]; metaAssessments: MetaResult[] }> {
  const conversation: { agent: string; content: string }[] = []
  const allMetaResults: MetaResult[] = []

  // Batch 1: Detective + Forensics in parallel
  const [detectiveOut, forensicsOut] = await Promise.all([
    withTimeout(runDetective(cloudtrailEvents), 'Detective timed out. Proceeding with partial data.'),
    withTimeout(runForensics(cloudtrailEvents), 'Forensics timed out. Proceeding with partial data.'),
  ])
  console.log('[Detective]', detectiveOut.slice(0, 200))
  console.log('[Forensics]', forensicsOut.slice(0, 200))
  conversation.push({ agent: 'Detective', content: detectiveOut })
  conversation.push({ agent: 'Forensics', content: forensicsOut })

  const meta1 = await runMetaCheck(['Detective', 'Forensics'], [detectiveOut, forensicsOut])
  console.log('[MetaCheck 1]', JSON.stringify(meta1))
  allMetaResults.push(...meta1)

  // Batch 2: Remediation + Validator in parallel
  const context1 = `DETECTIVE FINDINGS:\n${detectiveOut}\n\nFORENSICS FINDINGS:\n${forensicsOut}`
  const [remediationOut, validatorOut] = await Promise.all([
    withTimeout(runRemediation(context1), 'Remediation timed out.'),
    withTimeout(runValidator(context1), 'Validator timed out.'),
  ])
  console.log('[Remediation]', remediationOut.slice(0, 200))
  console.log('[Validator]', validatorOut.slice(0, 200))
  conversation.push({ agent: 'Remediation', content: remediationOut })
  conversation.push({ agent: 'Validator', content: validatorOut })

  const meta2 = await runMetaCheck(['Remediation', 'Validator'], [remediationOut, validatorOut])
  console.log('[MetaCheck 2]', JSON.stringify(meta2))
  allMetaResults.push(...meta2)

  // Authoritative timeline built directly from raw CloudTrail events — never use reporter's version
  const attackTimeline = buildAttackTimeline(cloudtrailEvents)

  // Provide structured timeline to reporter for context only
  const structuredTimeline = buildStructuredTimelineString(cloudtrailEvents)
  const agentContext = conversation.map((m) => `${m.agent.toUpperCase()}:\n${m.content}`).join('\n\n')
  const context2 = `STRUCTURED_TIMELINE:\n${structuredTimeline}\n\n${agentContext}`
  console.log('[Reporter context length]', context2.length)
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
    }),
    REPORTER_TIMEOUT_MS
  )
  conversation.push({ agent: 'Reporter', content: reporterOut })

  console.log('[Reporter raw output]', reporterOut.slice(0, 500))
  const meta3 = await runMetaCheck(['Reporter'], [reporterOut])
  console.log('[MetaCheck 3]', JSON.stringify(meta3))
  allMetaResults.push(...meta3)

  // Parse report JSON
  let report: any = {}
  try {
    const jsonMatch = reporterOut.match(/\{[\s\S]*\}/)
    report = jsonMatch ? JSON.parse(jsonMatch[0]) : { executiveSummary: reporterOut, severityScore: 'HIGH' }
  } catch {
    report = { executiveSummary: reporterOut, severityScore: 'HIGH' }
  }

  console.log('[Report parsed]', JSON.stringify(report).slice(0, 300))

  await supabaseAdmin
    .from('incidents')
    .update({
      status: 'resolved',
      severity: report.severityScore || 'HIGH',
      attack_type: techniqueId,
    })
    .eq('id', incidentId)

  const sentinelData = JSON.stringify({
    report,
    agent_conversation: conversation,
    attack_timeline: attackTimeline,
    meta_assessments: allMetaResults,
  })

  await supabaseAdmin.from('living_docs').insert({
    incident_id: incidentId,
    title: `sentinel-data-${incidentId}`,
    content_markdown: sentinelData,
    tags: ['sentinel-data'],
    severity: report.severityScore || 'HIGH',
    attack_type: techniqueId,
  })

  const markdown = format_markdown(report, conversation, attackTimeline)
  await supabaseAdmin.from('living_docs').insert({
    incident_id: incidentId,
    title: `Security Report: ${techniqueId}`,
    content_markdown: markdown,
    tags: [report.severityScore || 'HIGH', techniqueId],
    severity: report.severityScore || 'HIGH',
    attack_type: techniqueId,
  })

  return { report, conversation, attackTimeline, metaAssessments: allMetaResults }
}
