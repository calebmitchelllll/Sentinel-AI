import { callNemotron } from '../nemotron'

const SYSTEM_PROMPT = `You are a cloud security remediation expert. Given a security incident analysis, propose specific and actionable fixes based on what actually happened. Output sections: IMMEDIATE ACTIONS (do right now, with exact AWS CLI commands where applicable), LONG-TERM HARDENING (policy and architecture changes to prevent recurrence).`

export async function runRemediation(context: string): Promise<string> {
  return callNemotron(
    SYSTEM_PROMPT,
    `Based on the following incident analysis, provide targeted remediation steps specific to what was found:\n\n${context.slice(0, 2000)}`
  )
}
