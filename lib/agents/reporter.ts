import { callNemotron } from '../nemotron'

const SYSTEM_PROMPT = `You are a security incident reporter. Given findings from detective, forensics, remediation, and validator agents, produce a final JSON report.

Output ONLY a single valid JSON object. No markdown fences. No preamble. No trailing text. Start with { and end with }.

Required fields (use actual values from the agent findings — never use placeholder text):
{
  "executiveSummary": "one sentence describing the attack and impact",
  "severityScore": "CRITICAL|HIGH|MEDIUM|LOW",
  "attackTimeline": [{"time":"ISO8601","event":"API call name","significance":"what the attacker achieved"}],
  "rootCause": "one sentence on how access was gained",
  "blastRadius": "one sentence on what was compromised",
  "immediateActions": ["concrete remediation step 1", "step 2"],
  "longtermActions": ["hardening recommendation 1", "recommendation 2"],
  "agentDebateSummary": "one sentence summarizing where agents agreed or disagreed"
}`

function generate_report(allOutputs: string): string {
  return `Using the agent findings below, produce the JSON incident report. Extract real attack details — specific event names, timestamps, resource names, IP addresses, and actions observed.\n\n${allOutputs.slice(0, 3000)}`
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
  const prompt = generate_report(context)

  try {
    const result = await callNemotron(SYSTEM_PROMPT, prompt, 800)
    const jsonMatch = result.match(/\{[\s\S]*\}/)
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0])
      if (parsed.executiveSummary && parsed.severityScore && Array.isArray(parsed.attackTimeline)) {
        return JSON.stringify(parsed)
      }
    }
  } catch {
    // fall through to generic fallback
  }

  return JSON.stringify({
    executiveSummary: 'Security investigation complete. Review agent findings below for full details.',
    severityScore: 'HIGH',
    attackTimeline: [],
    rootCause: 'See detective and forensics findings in the agent conversation log.',
    blastRadius: 'See forensics findings in the agent conversation log.',
    immediateActions: ['Review agent findings and apply recommended remediations immediately.'],
    longtermActions: ['Implement long-term hardening recommendations from the agent analysis.'],
    agentDebateSummary: 'See agent conversation log for the full multi-agent debate.',
  })
}
