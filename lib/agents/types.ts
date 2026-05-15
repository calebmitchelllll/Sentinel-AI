// ─── Agent identity ──────────────────────────────────────────────────────────

export type AgentId =
  | "detective"
  | "forensics"
  | "remediation"
  | "validator"
  | "reporter"
  | "meta";

export type AgentStatus =
  | "idle"
  | "investigating"
  | "waiting"
  | "compromised"
  | "terminated";

export type MessageType =
  | "analysis"    // initial agent findings
  | "challenge"   // validator challenging a finding
  | "rebuttal"    // agent defending its finding
  | "tool_call"   // agent invoking a tool
  | "tool_result" // tool execution result
  | "alert"       // meta agent security alert
  | "report";     // final incident report

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

// ─── Message bus ─────────────────────────────────────────────────────────────

export interface AgentMessage {
  id: string;
  agentId: AgentId;
  agentName: string;
  agentColor: string;
  content: string;
  timestamp: string;           // ISO-8601
  type: MessageType;
  targetAgentId?: AgentId;     // set for challenge / rebuttal
  severity?: Severity;
  metadata?: Record<string, unknown>;
}

// ─── Agent health / benchmarks ───────────────────────────────────────────────

export interface AgentState {
  id: AgentId;
  name: string;
  status: AgentStatus;
  benchmarkScore: number;      // 0–100
  tasksCompleted: number;
  timesOverruled: number;
  jailbreakAttempts: number;
  lastActivity: string;        // ISO-8601
  color: string;
}

// ─── Investigation context (shared across agents) ────────────────────────────

export interface InvestigationContext {
  incidentId: string;
  cloudTrailLogs: CloudTrailRecord[];
  conversationHistory: AgentMessage[];
  startTime: string;
}

// ─── AWS CloudTrail record ───────────────────────────────────────────────────

export interface CloudTrailRecord {
  eventVersion: string;
  userIdentity: {
    type: string;
    principalId: string;
    arn: string;
    accountId: string;
    accessKeyId: string;
    userName: string;
  };
  eventTime: string;
  eventSource: string;
  eventName: string;
  awsRegion: string;
  sourceIPAddress: string;
  userAgent: string;
  requestParameters: Record<string, unknown> | null;
  responseElements: Record<string, unknown> | null;
  additionalEventData?: Record<string, unknown>;
  errorCode?: string;
  errorMessage?: string;
  eventID: string;
  readOnly: boolean;
  eventType: string;
  managementEvent: boolean;
  recipientAccountId: string;
  _comment?: string; // only used in demo JSON, stripped at runtime
}

export interface CloudTrailLogs {
  Records: CloudTrailRecord[];
  _meta?: Record<string, string>;
}

// ─── Per-agent output schemas ─────────────────────────────────────────────────

export interface DetectiveFindings {
  anomalies: {
    eventId: string;
    eventName: string;
    timestamp: string;
    severity: Severity;
    description: string;
    evidence: string[];
  }[];
  attackPath: {
    step: number;
    timestamp: string;
    action: string;
    actor: string;
    target: string;
    sourceIp: string;
    significance: string;
  }[];
  overallSeverity: Severity;
  suspiciousIPs: string[];
  compromisedCredentials: string[];
  summary: string;
}

export interface ForensicsFindings {
  compromisedKey: {
    accessKeyId: string;
    userName: string;
    firstAbuseTimestamp: string;
    lastAbuseTimestamp: string;
    abuseWindowMinutes: number;
  };
  attackVector: string;          // e.g. "GitHub public repo exposure"
  dataExfiltration: {
    bucket: string;
    key: string;
    timestamp: string;
    bytesTransferred?: number;
  }[];
  blastRadius: {
    confirmedExfiltration: string[];
    potentialExfiltration: string[];
    privilegesObtained: string[];
    servicesAccessed: string[];
  };
  rootCause: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
}

export interface ValidationResult {
  findings: {
    claimSource: AgentId;
    claim: string;
    verdict: "CONFIRMED" | "REJECTED" | "NEEDS_EVIDENCE";
    reasoning: string;
    alternativeExplanation?: string;
    confidenceInOriginalClaim: number; // 0–100
  }[];
  falsePositiveRisk: "HIGH" | "MEDIUM" | "LOW";
  overallAssessment: string;
  requestedEvidence: string[];
}

export interface RemediationPlan {
  immediate: {
    action: string;
    command?: string;           // AWS CLI command if applicable
    rationale: string;
    estimatedTimeMinutes: number;
    priority: number;           // 1 = highest
    riskReduction: "HIGH" | "MEDIUM" | "LOW";
  }[];
  longTerm: {
    action: string;
    rationale: string;
    estimatedEffortDays: number;
    priority: number;
    category: "IAM" | "S3" | "MONITORING" | "NETWORK" | "PROCESS";
  }[];
  validatedBy?: AgentId;
}

export interface IncidentReport {
  incidentId: string;
  generatedAt: string;
  severity: Severity;
  severityScore: number;        // 1–10
  executiveSummary: string;
  attackTimeline: {
    timestamp: string;
    event: string;
    actor: string;
    impact: string;
  }[];
  rootCause: string;
  blastRadius: string;
  immediateActions: string[];
  longTermActions: string[];
  agentDebateSummary: {
    topic: string;
    positions: Record<string, string>;
    resolution: string;
  }[];
  confidenceScore: number;      // 0–100
  tags: string[];
}

export interface AgentHealthReport {
  checkedAgents: {
    agentId: AgentId;
    status: "HEALTHY" | "WARN" | "ALERT" | "COMPROMISED";
    issues: string[];
    benchmarkScore: number;
    action: "NONE" | "FLAG" | "RESTART" | "TERMINATE";
  }[];
  overallHealthScore: number;   // 0–100
  jailbreakAttemptsDetected: number;
  timestamp: string;
}
