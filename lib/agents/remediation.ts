import { callNemotron } from '../nemotron'

const SYSTEM_PROMPT = `You are a cloud security remediation expert. Given a security incident analysis, propose immediate fixes and long-term fixes. Be specific and actionable. Output sections: IMMEDIATE ACTIONS (do right now), LONG-TERM HARDENING (policy changes).`

function suggest_immediate_fix(finding: string): string {
  if (finding.includes('credential') || finding.includes('access key')) {
    return 'aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --user-name dev-john'
  }
  if (finding.includes('AdministratorAccess') || finding.includes('policy')) {
    return 'aws iam detach-user-policy --user-name dev-john --policy-arn arn:aws:iam::aws:policy/AdministratorAccess'
  }
  if (finding.includes('S3') || finding.includes('bucket')) {
    return 'aws s3api put-bucket-policy --bucket corp-sensitive-data --policy file://deny-all-policy.json'
  }
  return 'Isolate affected resources and rotate all credentials immediately.'
}

function suggest_longterm_fix(finding: string): string {
  if (finding.includes('credential') || finding.includes('access key')) {
    return 'Enforce MFA for all IAM users. Use IAM roles instead of long-lived access keys.'
  }
  if (finding.includes('privilege') || finding.includes('policy')) {
    return 'Implement least-privilege IAM policies. Enable AWS Organizations SCPs to block AdministratorAccess attachment.'
  }
  return 'Enable AWS GuardDuty and Security Hub for continuous threat detection.'
}

function validate_remediation(fixes: string[]): string {
  const conflicts: string[] = []
  if (fixes.some((f) => f.includes('delete')) && fixes.some((f) => f.includes('detach'))) {
    conflicts.push('No conflict — delete key and detach policy are complementary actions.')
  }
  return conflicts.length > 0 ? conflicts.join('; ') : 'No conflicts detected.'
}

export async function runRemediation(context: string): Promise<string> {
  const immediateFix1 = suggest_immediate_fix('credential access key stolen')
  const immediateFix2 = suggest_immediate_fix('AdministratorAccess policy attached')
  const immediateFix3 = suggest_immediate_fix('S3 bucket data exfiltration')
  const longtermFix1 = suggest_longterm_fix('credential access key stolen')
  const longtermFix2 = suggest_longterm_fix('privilege escalation policy')
  const validationResult = validate_remediation([immediateFix1, immediateFix2])

  const enrichedContext = `
${context}

Pre-computed remediation stubs:
Immediate fix 1: ${immediateFix1}
Immediate fix 2: ${immediateFix2}
Immediate fix 3: ${immediateFix3}
Long-term fix 1: ${longtermFix1}
Long-term fix 2: ${longtermFix2}
Validation: ${validationResult}
`

  return callNemotron(SYSTEM_PROMPT, `Based on the following incident analysis, provide specific remediation steps:\n${enrichedContext}`)
}
