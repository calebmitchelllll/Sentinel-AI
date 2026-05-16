/**
 * CloudTrail event parser + suspicion scorer for SentinelAI.
 * Converts raw CloudTrailRecord objects into enriched ParsedCloudTrailEvent
 * objects with a 0–10 suspicion score that agents can use directly.
 */

import { CloudTrailRecord, CloudTrailLogs } from "./agents/types";

// ─── Output type ──────────────────────────────────────────────────────────────

export interface ParsedCloudTrailEvent {
  eventId: string;
  eventTime: string;
  eventName: string;
  eventSource: string;
  sourceIPAddress: string;
  userAgent: string;
  userIdentity: {
    type: string;
    userName: string;
    accessKeyId: string;
    arn: string;
    accountId: string;
    principalId: string;
  };
  requestParameters: Record<string, unknown> | null;
  responseElements: Record<string, unknown> | null;
  errorCode?: string;
  errorMessage?: string;
  awsRegion: string;
  suspicionScore: number;    // 0–10 (10 = extremely suspicious)
  suspicionReasons: string[];
  isSuspicious: boolean;     // true if score >= 3
}

// ─── Scoring rules ────────────────────────────────────────────────────────────

// Tor exit nodes and known attacker VPN ranges
const SUSPICIOUS_IP_PATTERNS = [
  /^185\.220\./,      // Tor exit nodes (Quintex Alliance)
  /^185\.234\.219\./, // Tor / bulletproof hosting
  /^199\.87\.154\./,  // Tor exit nodes
  /^104\.244\./,      // Twitter/Tor exit
  /^185\.107\./,
  /^91\.108\./,
  /^176\.10\./,       // Tor Project infra
];

// Kali, Parrot, and common attacker CLI patterns in user agents
const SUSPICIOUS_UA_PATTERNS = [
  /kali/i,
  /parrot.os/i,
  /metasploit/i,
  /nmap/i,
  /sqlmap/i,
  /burpsuite/i,
  /python-requests/i, // common in automated attack scripts
  /go-http-client/i,  // Stratus Red Team uses Go
  /hacktools/i,
];

// Immediate high-severity events (score +4)
const CRITICAL_EVENTS = new Set([
  "AttachUserPolicy",
  "PutUserPolicy",
  "CreateAccessKey",
  "CreateLoginProfile",
  "UpdateLoginProfile",
  "DeleteTrail",
  "StopLogging",
  "CreatePolicyVersion",
  "SetDefaultPolicyVersion",
  "PutBucketPolicy",
  "PutBucketAcl",
]);

// Security-relevant events worth investigating (score +2)
const NOTABLE_EVENTS = new Set([
  "GetCallerIdentity",
  "ListRoles",
  "ListUsers",
  "ListBuckets",
  "ListObjectsV2",
  "ListObjects",
  "ListAttachedUserPolicies",
  "ListAttachedRolePolicies",
  "AssumeRole",
  "CreateRole",
  "CreateUser",
  "DeleteUser",
  "DetachUserPolicy",
  "GetObject",
  "ConsoleLogin",
  "GetBucketPolicy",
  "GetSessionToken",
]);

// Strings in requestParameters that elevate score
const SENSITIVE_PARAM_PATTERNS: { pattern: RegExp; score: number; label: string }[] = [
  { pattern: /AdministratorAccess/,             score: 3, label: "AdministratorAccess policy referenced" },
  { pattern: /arn:aws:iam::aws:policy/,          score: 1, label: "AWS managed policy attached" },
  { pattern: /sensitive|employees|finance|hr\b|payroll|secret/i, score: 2, label: "Sensitive data path referenced" },
  { pattern: /CreateAccessKey/i,                 score: 1, label: "Access key creation in params" },
];

// ─── Core parser ──────────────────────────────────────────────────────────────

function scoreEvent(record: CloudTrailRecord): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  let score = 0;

  // 1. Event name severity
  if (CRITICAL_EVENTS.has(record.eventName)) {
    score += 4;
    reasons.push(`Critical security event: ${record.eventName}`);
  } else if (NOTABLE_EVENTS.has(record.eventName)) {
    score += 2;
    reasons.push(`Security-relevant event: ${record.eventName}`);
  }

  // 2. Source IP
  const ip = record.sourceIPAddress ?? "";
  for (const pattern of SUSPICIOUS_IP_PATTERNS) {
    if (pattern.test(ip)) {
      score += 3;
      reasons.push(`Source IP ${ip} matches known malicious range`);
      break;
    }
  }

  // 3. User agent
  const ua = record.userAgent ?? "";
  for (const pattern of SUSPICIOUS_UA_PATTERNS) {
    if (pattern.test(ua)) {
      score += 2;
      reasons.push(`Suspicious user agent: ${ua.slice(0, 60)}`);
      break;
    }
  }

  // 4. Sensitive request parameters
  const paramsStr = JSON.stringify(record.requestParameters ?? {});
  for (const { pattern, score: s, label } of SENSITIVE_PARAM_PATTERNS) {
    if (pattern.test(paramsStr)) {
      score += s;
      reasons.push(label);
    }
  }

  // 5. Access denied / error (attempted but blocked — still suspicious)
  if (record.errorCode) {
    score += 1;
    reasons.push(`Failed with ${record.errorCode}: ${record.errorMessage ?? ""}`);
  }

  // 6. Off-hours access (00:00–06:00 UTC)
  const hour = new Date(record.eventTime).getUTCHours();
  if (hour < 6) {
    score += 1;
    reasons.push(`Off-hours access at ${String(hour).padStart(2, "0")}:00 UTC`);
  }

  // 7. Non-AWS service source IP (attacker calling directly, not from console/service)
  if (ip && !ip.endsWith(".amazonaws.com") && !ip.startsWith("10.") && !ip.startsWith("172.16.")) {
    const isCorp = ip === "203.0.113.10"; // adjust for real corp IP if known
    if (!isCorp && CRITICAL_EVENTS.has(record.eventName)) {
      score += 1;
      reasons.push(`Critical action from external IP: ${ip}`);
    }
  }

  return { score: Math.min(score, 10), reasons };
}

export function parseCloudTrailEvent(record: CloudTrailRecord): ParsedCloudTrailEvent {
  const { score, reasons } = scoreEvent(record);

  return {
    eventId: record.eventID,
    eventTime: record.eventTime,
    eventName: record.eventName,
    eventSource: record.eventSource,
    sourceIPAddress: record.sourceIPAddress,
    userAgent: record.userAgent,
    userIdentity: {
      type: record.userIdentity.type,
      userName: record.userIdentity.userName,
      accessKeyId: record.userIdentity.accessKeyId,
      arn: record.userIdentity.arn,
      accountId: record.userIdentity.accountId,
      principalId: record.userIdentity.principalId,
    },
    requestParameters: record.requestParameters,
    responseElements: record.responseElements,
    errorCode: record.errorCode,
    errorMessage: record.errorMessage,
    awsRegion: record.awsRegion,
    suspicionScore: score,
    suspicionReasons: reasons,
    isSuspicious: score >= 3,
  };
}

export function parseCloudTrailEvents(records: CloudTrailRecord[]): ParsedCloudTrailEvent[] {
  return records
    .filter((r) => !r._comment) // strip demo metadata
    .map(parseCloudTrailEvent)
    .sort((a, b) => new Date(a.eventTime).getTime() - new Date(b.eventTime).getTime());
}

export function filterSuspicious(events: ParsedCloudTrailEvent[]): ParsedCloudTrailEvent[] {
  return events.filter((e) => e.isSuspicious);
}

/**
 * Convert parsed events back to the CloudTrailLogs format the agents consume.
 * Embeds suspicion metadata so agents can reference scores in their analysis.
 */
export function toAgentLogs(events: ParsedCloudTrailEvent[]): CloudTrailLogs {
  return {
    Records: events.map((e) => ({
      eventVersion: "1.08",
      userIdentity: {
        type: e.userIdentity.type,
        principalId: e.userIdentity.principalId,
        arn: e.userIdentity.arn,
        accountId: e.userIdentity.accountId,
        accessKeyId: e.userIdentity.accessKeyId,
        userName: e.userIdentity.userName,
      },
      eventTime: e.eventTime,
      eventSource: e.eventSource,
      eventName: e.eventName,
      awsRegion: e.awsRegion,
      sourceIPAddress: e.sourceIPAddress,
      userAgent: e.userAgent,
      requestParameters: e.requestParameters,
      responseElements: e.responseElements,
      errorCode: e.errorCode,
      errorMessage: e.errorMessage,
      eventID: e.eventId,
      readOnly: false,
      eventType: "AwsApiCall",
      managementEvent: true,
      recipientAccountId: e.userIdentity.accountId,
      // _comment carries suspicion metadata — agents can read it as context
      _comment: e.isSuspicious
        ? `[SUSPICIOUS score=${e.suspicionScore}] ${e.suspicionReasons.join("; ")}`
        : undefined,
    })),
  };
}

/**
 * Full pipeline: raw CloudTrailLogs → parsed → filtered to suspicious only → agent-ready logs.
 * This is the main function most callers should use.
 */
export function processLogsForAgents(logs: CloudTrailLogs): {
  all: ParsedCloudTrailEvent[];
  suspicious: ParsedCloudTrailEvent[];
  agentLogs: CloudTrailLogs;
  stats: {
    total: number;
    suspicious: number;
    criticalCount: number;
    uniqueIPs: string[];
    topSuspiciousEvents: string[];
  };
} {
  const all = parseCloudTrailEvents(logs.Records);
  const suspicious = filterSuspicious(all);
  // Feed agents only suspicious events to keep context tight; fall back to all if none flagged
  const toFeed = suspicious.length > 0 ? suspicious : all;
  const agentLogs = toAgentLogs(toFeed);

  const criticalCount = all.filter((e) => e.suspicionScore >= 7).length;
  const uniqueIPs = [...new Set(suspicious.map((e) => e.sourceIPAddress))];
  const eventCounts = suspicious.reduce<Record<string, number>>((acc, e) => {
    acc[e.eventName] = (acc[e.eventName] ?? 0) + 1;
    return acc;
  }, {});
  const topSuspiciousEvents = Object.entries(eventCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name]) => name);

  return {
    all,
    suspicious,
    agentLogs,
    stats: { total: all.length, suspicious: suspicious.length, criticalCount, uniqueIPs, topSuspiciousEvents },
  };
}
