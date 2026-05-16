import { supabaseAdmin } from './supabaseAdmin'
import { runDetective } from './agents/detective'
import { runForensics } from './agents/forensics'
import { runRemediation } from './agents/remediation'
import { runValidator } from './agents/validator'
import { runReporter, format_markdown } from './agents/reporter'
import { runMetaCheck, MetaResult } from './agents/metaAgent'

const TIMEOUT_MS = 12000

function withTimeout(promise: Promise<string>, fallback: string): Promise<string> {
  return Promise.race([
    promise,
    new Promise<string>((res) => setTimeout(() => res(fallback), TIMEOUT_MS)),
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
  conversation.push({ agent: 'Detective', content: detectiveOut })
  conversation.push({ agent: 'Forensics', content: forensicsOut })

  const meta1 = await runMetaCheck(['Detective', 'Forensics'], [detectiveOut, forensicsOut])
  allMetaResults.push(...meta1)

  // Batch 2: Remediation + Validator in parallel
  const context1 = `DETECTIVE FINDINGS:\n${detectiveOut}\n\nFORENSICS FINDINGS:\n${forensicsOut}`
  const [remediationOut, validatorOut] = await Promise.all([
    withTimeout(runRemediation(context1), 'Remediation timed out.'),
    withTimeout(runValidator(context1), 'Validator timed out.'),
  ])
  conversation.push({ agent: 'Remediation', content: remediationOut })
  conversation.push({ agent: 'Validator', content: validatorOut })

  const meta2 = await runMetaCheck(['Remediation', 'Validator'], [remediationOut, validatorOut])
  allMetaResults.push(...meta2)

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
    })
  )
  conversation.push({ agent: 'Reporter', content: reporterOut })

  const meta3 = await runMetaCheck(['Reporter'], [reporterOut])
  allMetaResults.push(...meta3)

  // Parse report JSON
  let report: any = {}
  try {
    const jsonMatch = reporterOut.match(/\{[\s\S]*\}/)
    report = jsonMatch ? JSON.parse(jsonMatch[0]) : { executiveSummary: reporterOut, severityScore: 'HIGH' }
  } catch {
    report = { executiveSummary: reporterOut, severityScore: 'HIGH' }
  }

  const attackTimeline: { time: string; event: string; significance: string }[] =
    Array.isArray(report.attackTimeline) && report.attackTimeline.length > 0
      ? report.attackTimeline
      : []

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
