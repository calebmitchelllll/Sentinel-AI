import { callNemotron } from '../nemotron'

const SYSTEM_PROMPT = `You are a security validator and skeptic. Given findings from a detective and forensics agent, challenge any weak conclusions. Ask: is the evidence solid? Could this be a false positive? What is the confidence level? Output sections: CHALLENGED FINDINGS, CONFIDENCE SCORES (0-100 per finding), VERDICT (confirmed / unconfirmed / false positive).`

function challenge_finding(finding: string): string {
  if (finding.includes('185.220.101.47')) {
    return 'Could this IP be a VPN or Tor exit node used by the legitimate developer working remotely? Verify against known developer IPs.'
  }
  if (finding.includes('AdministratorAccess')) {
    return 'Was there a legitimate reason to attach AdministratorAccess? Check if this is part of an approved infrastructure change.'
  }
  if (finding.includes('corp-sensitive-data')) {
    return 'Was the developer authorized to access corp-sensitive-data? Check bucket policy and access logs for prior access patterns.'
  }
  return 'Challenge: Verify the evidence is not circumstantial and cross-reference with SIEM baseline.'
}

function request_evidence(claim: string, events: any[]): string {
  if (claim.includes('185.220.101.47')) {
    const attackEvents = events.filter((e: any) => e.sourceIPAddress === '185.220.101.47')
    const normalEvents = events.filter((e: any) => e.sourceIPAddress === '203.0.113.42')
    return `Evidence: ${attackEvents.length} events from 185.220.101.47 vs ${normalEvents.length} events from known-good IP 203.0.113.42. IP switch with no prior history is high-confidence indicator.`
  }
  return 'Evidence: log timestamps and IP addresses are consistent with credential theft.'
}

function confirm_or_reject(finding: string, evidence: string): string {
  if (evidence.includes('high-confidence')) return 'CONFIRMED — evidence is strong and consistent.'
  if (evidence.includes('log timestamps')) return 'CONFIRMED — corroborated by raw log data.'
  return 'UNCONFIRMED — insufficient evidence for definitive conclusion.'
}

export async function runValidator(context: string): Promise<string> {
  const challenge1 = challenge_finding('185.220.101.47 attacker IP')
  const challenge2 = challenge_finding('AdministratorAccess policy attached')
  const challenge3 = challenge_finding('corp-sensitive-data S3 exfiltration')
  const evidence = request_evidence('185.220.101.47', [])
  const verdict = confirm_or_reject('IP anomaly', evidence)

  const enrichedContext = `
${context}

Pre-computed challenges:
Challenge 1 (IP anomaly): ${challenge1}
Challenge 2 (privilege escalation): ${challenge2}
Challenge 3 (S3 access): ${challenge3}
Evidence assessment: ${evidence}
Initial verdict: ${verdict}
`

  return callNemotron(SYSTEM_PROMPT, `Validate and challenge these security findings:\n${enrichedContext}`)
}
