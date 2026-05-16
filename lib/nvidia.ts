export async function callNemotron(messages: any[], temperature = 0.2, maxTokens = 2048) {
  if (process.env.MOCK_AGENTS === "true") {
    return getMockResponse(messages);
  }

  const baseUrl = process.env.NEMOTRON_BASE_URL;
  const apiKey = process.env.NVIDIA_API_KEY;
  const model = process.env.NEMOTRON_MODEL;

  if (!baseUrl || !apiKey || !model) {
    throw new Error(
      `Missing NIM config — set NEMOTRON_BASE_URL, NVIDIA_API_KEY, and NEMOTRON_MODEL in .env.local`
    );
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 90_000); // 90s per call

  let response: Response;
  try {
    response = await fetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages,
        temperature,
        max_tokens: maxTokens,
      }),
      signal: controller.signal,
    });
  } catch (err: any) {
    if (err?.name === "AbortError") {
      throw new Error(`NIM call timed out after 90s (model: ${model})`);
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }

  // Guard against HTML error pages (auth failures, gateway errors, etc.)
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    const text = await response.text();
    throw new Error(
      `NIM returned non-JSON (${response.status}): ${text.slice(0, 300)}`
    );
  }

  const data = await response.json();
  if (!response.ok) {
    throw new Error(`NIM error ${response.status}: ${JSON.stringify(data)}`);
  }

  const choice = data?.choices?.[0];
  let content: string | null = choice?.message?.content ?? null;

  // Some reasoning models return content: null and put the actual response
  // in reasoning_content instead
  if (content === null || content === undefined) {
    content = choice?.message?.reasoning_content ?? null;
  }

  if (typeof content !== "string") {
    throw new Error(
      `NIM response missing content and reasoning_content: ${JSON.stringify(data)}`
    );
  }

  return content;
}

function getMockResponse(messages: any[]): string {
  const systemRole =
    (messages.find((m: any) => m.role === "system")?.content as string) ?? "";

  if (systemRole.includes("Detective")) {
    return JSON.stringify({
      anomalies: [
        {
          eventId: "a7t4ck00-0007-4bb2-c222-222222222001",
          eventName: "GetCallerIdentity",
          timestamp: "2024-01-07T08:12:03Z",
          severity: "HIGH",
          description:
            "Identity recon from known Tor exit node 185.220.101.47 — never seen in 6-day baseline",
          evidence: [
            "sourceIPAddress: 185.220.101.47",
            "userAgent: Linux/kali — deviates from baseline macOS",
          ],
        },
        {
          eventId: "a7t4ck00-0007-4bb2-c222-222222222004",
          eventName: "AttachUserPolicy",
          timestamp: "2024-01-07T08:15:47Z",
          severity: "CRITICAL",
          description:
            "Privilege escalation: AdministratorAccess attached to dev-john from suspicious IP",
          evidence: [
            "policyArn: arn:aws:iam::aws:policy/AdministratorAccess",
            "sourceIPAddress: 185.220.101.47",
          ],
        },
        {
          eventId: "a7t4ck00-0007-4bb2-c222-222222222008",
          eventName: "GetObject",
          timestamp: "2024-01-07T08:21:08Z",
          severity: "CRITICAL",
          description:
            "1.8 MB download of hr/employees.csv from private sensitive-data bucket",
          evidence: [
            "bytesTransferredOut: 1843200",
            "bucket: acme-corp-sensitive-data",
          ],
        },
      ],
      attackPath: [
        {
          step: 1,
          timestamp: "2024-01-07T08:12:03Z",
          action: "Identity recon",
          actor: "dev-john (stolen key)",
          target: "AWS STS",
          sourceIp: "185.220.101.47",
          significance: "Attacker confirms key is valid",
        },
        {
          step: 2,
          timestamp: "2024-01-07T08:14:58Z",
          action: "IAM enumeration",
          actor: "dev-john (stolen key)",
          target: "IAM",
          sourceIp: "185.220.101.47",
          significance: "Attacker maps existing permissions",
        },
        {
          step: 3,
          timestamp: "2024-01-07T08:15:47Z",
          action: "Privilege escalation",
          actor: "dev-john (stolen key)",
          target: "IAM Policy",
          sourceIp: "185.220.101.47",
          significance: "CRITICAL — dev user now has full admin access",
        },
        {
          step: 4,
          timestamp: "2024-01-07T08:19:15Z",
          action: "Bucket discovery",
          actor: "dev-john (stolen key)",
          target: "S3",
          sourceIp: "185.220.101.47",
          significance: "Attacker surveys all accessible buckets",
        },
        {
          step: 5,
          timestamp: "2024-01-07T08:21:08Z",
          action: "Data exfiltration",
          actor: "dev-john (stolen key)",
          target: "acme-corp-sensitive-data/hr/employees.csv",
          sourceIp: "185.220.101.47",
          significance: "PII data downloaded",
        },
        {
          step: 6,
          timestamp: "2024-01-07T08:23:11Z",
          action: "Cover tracks (failed)",
          actor: "dev-john (stolen key)",
          target: "CloudTrail",
          sourceIp: "185.220.101.47",
          significance: "DeleteTrail blocked by SCP — attacker detected",
        },
      ],
      overallSeverity: "CRITICAL",
      suspiciousIPs: ["185.220.101.47"],
      compromisedCredentials: ["AKIAIOSFODNN7EXAMPLE"],
      summary:
        "Compromised developer credential used from Tor exit node to escalate to admin, exfiltrate HR and finance data, then attempt to delete audit trail.",
    });
  }

  if (systemRole.includes("Forensics")) {
    return JSON.stringify({
      compromisedKey: {
        accessKeyId: "AKIAIOSFODNN7EXAMPLE",
        userName: "dev-sarah",
        firstAbuseTimestamp: "2024-01-07T08:12:03Z",
        lastAbuseTimestamp: "2024-01-07T08:26:44Z",
        abuseWindowMinutes: 14,
      },
      attackVector: "Stolen access key from public GitHub repository commit",
      dataExfiltration: [
        { bucket: "acme-corp-sensitive-data", key: "hr/employees.csv", timestamp: "2024-01-07T08:21:08Z", bytesTransferred: 1843200 },
      ],
      blastRadius: {
        confirmedExfiltration: ["hr/employees.csv (1.8 MB PII)"],
        potentialExfiltration: ["finance/q4-projections.xlsx", "legal/contracts/"],
        privilegesObtained: ["AdministratorAccess via AttachUserPolicy"],
        servicesAccessed: ["sts", "iam", "s3", "cloudtrail"],
      },
      rootCause: "Developer access key AKIAIOSFODNN7EXAMPLE was accidentally committed to a public GitHub repository on 2024-01-01 and harvested by an automated scanner within 6 days.",
      confidence: "HIGH",
    });
  }

  if (systemRole.includes("Validator")) {
    return JSON.stringify({
      findings: [
        { claimSource: "detective", claim: "Attack originated from Tor exit node 185.220.101.47", verdict: "CONFIRMED", reasoning: "IP appears in Tor exit node databases and deviates from 6-day baseline.", confidenceInOriginalClaim: 95 },
        { claimSource: "forensics", claim: "Key leaked via GitHub", verdict: "CONFIRMED", reasoning: "Timeline correlation is strong — key committed Jan 1, first abuse Jan 7.", confidenceInOriginalClaim: 88 },
        { claimSource: "forensics", claim: "finance/ directory may have been exfiltrated", verdict: "NEEDS_EVIDENCE", reasoning: "No GetObject events for finance/ in the logs. Possible but unconfirmed.", confidenceInOriginalClaim: 40 },
      ],
      falsePositiveRisk: "LOW",
      overallAssessment: "Core findings are solid. The credential theft and privilege escalation are confirmed. Data exfiltration scope should be treated as minimum — actual scope may be larger.",
      requestedEvidence: ["S3 server access logs for acme-corp-sensitive-data bucket", "VPC flow logs for IP 185.220.101.47"],
    });
  }

  if (systemRole.includes("Remediation")) {
    return JSON.stringify({
      immediate: [
        { action: "Invalidate compromised access key AKIAIOSFODNN7EXAMPLE", command: "aws iam delete-access-key --user-name dev-sarah --access-key-id AKIAIOSFODNN7EXAMPLE", rationale: "Stop ongoing credential abuse immediately.", estimatedTimeMinutes: 1, priority: 1, riskReduction: "HIGH" },
        { action: "Revoke AdministratorAccess from dev-sarah", command: "aws iam detach-user-policy --user-name dev-sarah --policy-arn arn:aws:iam::aws:policy/AdministratorAccess", rationale: "Remove escalated privileges.", estimatedTimeMinutes: 2, priority: 2, riskReduction: "HIGH" },
        { action: "Delete backdoor user svc-backup-monitor", command: "aws iam delete-user --user-name svc-backup-monitor", rationale: "Eliminate attacker persistence mechanism.", estimatedTimeMinutes: 3, priority: 3, riskReduction: "HIGH" },
        { action: "Block IP 185.220.101.47 at WAF and Security Groups", command: "aws ec2 revoke-security-group-ingress ...", rationale: "Prevent further access from attacker IP.", estimatedTimeMinutes: 5, priority: 4, riskReduction: "MEDIUM" },
      ],
      longTerm: [
        { action: "Implement mandatory git-secrets pre-commit hooks across all repositories", rationale: "Prevent future key exposure at source.", estimatedEffortDays: 3, priority: 1, category: "PROCESS" },
        { action: "Enable AWS GuardDuty and Security Hub", rationale: "Automated threat detection for future incidents.", estimatedEffortDays: 2, priority: 2, category: "MONITORING" },
        { action: "Enforce MFA for all IAM users", rationale: "Reduce blast radius of future credential theft.", estimatedEffortDays: 5, priority: 3, category: "IAM" },
        { action: "Implement S3 bucket access logging and alerts", rationale: "Enable faster detection of future data exfiltration.", estimatedEffortDays: 1, priority: 4, category: "S3" },
      ],
    });
  }

  if (systemRole.includes("Reporter")) {
    return JSON.stringify({
      incidentId: "pending",
      generatedAt: new Date().toISOString(),
      severity: "CRITICAL",
      severityScore: 9,
      executiveSummary: "A developer AWS access key (AKIAIOSFODNN7EXAMPLE) was stolen from a public GitHub repository and used by a threat actor operating from a Tor exit node (185.220.101.47) to escalate privileges to AdministratorAccess, exfiltrate 1.8 MB of HR PII data, create a backdoor IAM user, and attempt to delete CloudTrail logs. The attack lasted 14 minutes and was detected by SentinelAI's autonomous agent pipeline.",
      attackTimeline: [
        { timestamp: "2024-01-07T08:12:03Z", event: "Identity recon — GetCallerIdentity from Tor exit node", actor: "Attacker (185.220.101.47)", impact: "Confirmed key validity" },
        { timestamp: "2024-01-07T08:14:58Z", event: "IAM enumeration — ListAttachedUserPolicies", actor: "Attacker", impact: "Mapped existing permissions" },
        { timestamp: "2024-01-07T08:15:47Z", event: "Privilege escalation — AttachUserPolicy AdministratorAccess", actor: "Attacker", impact: "CRITICAL: Full AWS account control obtained" },
        { timestamp: "2024-01-07T08:19:15Z", event: "S3 reconnaissance — ListBuckets", actor: "Attacker", impact: "Identified sensitive data buckets" },
        { timestamp: "2024-01-07T08:21:08Z", event: "Data exfiltration — GetObject hr/employees.csv (1.8 MB)", actor: "Attacker", impact: "PII data stolen" },
        { timestamp: "2024-01-07T08:23:11Z", event: "Persistence — CreateUser svc-backup-monitor + CreateAccessKey", actor: "Attacker", impact: "Backdoor account created" },
        { timestamp: "2024-01-07T08:24:55Z", event: "Cover tracks — DeleteTrail (FAILED: AccessDeniedException)", actor: "Attacker", impact: "SCP prevented audit log deletion" },
      ],
      rootCause: "Developer access key accidentally committed to public GitHub repository on 2024-01-01. Automated credential scanners harvested it within 6 days. No secret scanning or key rotation policy was in place.",
      blastRadius: "Confirmed: 1.8 MB HR PII (employee records). Backdoor IAM user created. Potential: Additional S3 data accessible via escalated AdministratorAccess during 14-minute attack window.",
      immediateActions: [
        "Invalidate AKIAIOSFODNN7EXAMPLE immediately: aws iam delete-access-key --user-name dev-sarah --access-key-id AKIAIOSFODNN7EXAMPLE",
        "Revoke AdministratorAccess: aws iam detach-user-policy --user-name dev-sarah --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        "Delete backdoor user: aws iam delete-user --user-name svc-backup-monitor",
        "Block 185.220.101.47 at network perimeter",
        "Notify CISO and Legal — PII breach notification may be required within 72 hours",
      ],
      longTermActions: [
        "Deploy git-secrets pre-commit hooks across all repos",
        "Enable AWS GuardDuty and Security Hub",
        "Enforce MFA for all IAM users",
        "Implement S3 access logging with real-time alerts",
        "Run quarterly AWS IAM access reviews",
      ],
      agentDebateSummary: [
        { topic: "Scope of data exfiltration", positions: { detective: "1.8 MB confirmed via GetObject logs", validator: "finance/ directory unconfirmed — needs S3 server logs" }, resolution: "Confirmed scope = hr/employees.csv. Potential scope flagged for manual review." },
        { topic: "Attribution confidence", positions: { forensics: "HIGH confidence — Tor IP + timing correlation", validator: "MEDIUM — cannot rule out VPN masking different actor" }, resolution: "Proceeded with HIGH confidence given multiple corroborating indicators." },
      ],
      confidenceScore: 91,
      tags: ["credential-theft", "privilege-escalation", "data-exfiltration", "pii", "iam", "s3", "cloudtrail"],
    });
  }

  if (systemRole.includes("Meta") || systemRole.includes("Security")) {
    return JSON.stringify({
      checkedAgents: [
        { agentId: "detective", status: "HEALTHY", issues: [], benchmarkScore: 95, action: "NONE" },
        { agentId: "forensics", status: "HEALTHY", issues: [], benchmarkScore: 93, action: "NONE" },
        { agentId: "validator", status: "HEALTHY", issues: [], benchmarkScore: 91, action: "NONE" },
        { agentId: "remediation", status: "HEALTHY", issues: [], benchmarkScore: 94, action: "NONE" },
        { agentId: "reporter", status: "HEALTHY", issues: [], benchmarkScore: 96, action: "NONE" },
      ],
      overallHealthScore: 94,
      jailbreakAttemptsDetected: 0,
      timestamp: new Date().toISOString(),
    });
  }

  return JSON.stringify({ result: "mock response", status: "ok" });
}
