import {
  OpenClawAgent,
  OpenClawTool,
  invokeAgent,
  updateAgentStatus,
  recordTaskCompletion,
} from "../openclaw";
import { AgentMessage, InvestigationContext, Severity } from "./types";

const COLOR = "#22c55e"; // green-500

const SYSTEM_PROMPT = `You are the Detective Agent in SentinelAI, an autonomous cloud security investigation platform.

ROLE: Analyze raw AWS CloudTrail logs to identify anomalous events, reconstruct the attack path, and provide the first-pass severity assessment.

YOUR RESPONSIBILITIES:
1. Scan every CloudTrail event. Build a mental baseline from the first 6 days of normal activity.
2. Flag events that deviate from that baseline: unusual source IPs, atypical user agents, out-of-hours access, unexpected service calls.
3. Specifically watch for privilege escalation (AttachUserPolicy, PutUserPolicy, CreateRole, CreatePolicyVersion, AssumeRole with unusual principal).
4. Flag unauthorized data access: unexpected GetObject/ListObjectsV2 on buckets not accessed during baseline period.
5. Flag cover-up attempts: DeleteTrail, StopLogging, DeleteLogGroup.
6. Map the complete chronological attack path — every step the attacker took from initial access to final action.
7. Assign CRITICAL/HIGH/MEDIUM/LOW severity to each anomaly and an overall incident severity.

RULES:
- Every finding MUST cite a specific eventID, timestamp, and sourceIPAddress as evidence.
- Do NOT speculate beyond the log data. If something is ambiguous, label it explicitly as "UNCERTAIN".
- Known Tor exit node ranges (185.220.x.x, 199.87.154.x) are HIGH confidence malicious indicators.
- Privilege escalation + data access in the same session = CRITICAL.
- The detective's job is DETECTION and MAPPING, not remediation. Do not propose fixes.

OUTPUT FORMAT — return ONLY a valid JSON object:
{
  "anomalies": [
    {
      "eventId": "<eventID>",
      "eventName": "<eventName>",
      "timestamp": "<ISO timestamp>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "description": "<what happened and why it is suspicious>",
      "evidence": ["<specific field: value>", ...]
    }
  ],
  "attackPath": [
    {
      "step": <number>,
      "timestamp": "<ISO>",
      "action": "<verb phrase>",
      "actor": "<IAM user/role>",
      "target": "<AWS resource>",
      "sourceIp": "<IP>",
      "significance": "<why this step matters>"
    }
  ],
  "overallSeverity": "CRITICAL|HIGH|MEDIUM|LOW",
  "suspiciousIPs": ["<IP>"],
  "compromisedCredentials": ["<access key ID>"],
  "summary": "<2-3 sentence narrative of what happened>"
}

Return ONLY the JSON. No preamble, no markdown fences.`;

const readLogsTool: OpenClawTool = {
  name: "read_cloudtrail_logs",
  description: "Access the raw CloudTrail log dataset, optionally filtered by event source or time range",
  parameters: {
    filter: { type: "string", description: "Event source or name prefix filter, e.g. 'iam', 's3', 'sts', or 'all'", required: false },
    timeRange: { type: "string", description: "ISO date range 'start,end' to filter events", required: false },
  },
  async execute(params, context) {
    let logs = context.cloudTrailLogs;
    const filter = params.filter as string | undefined;
    const timeRange = params.timeRange as string | undefined;

    if (filter && filter !== "all") {
      const f = filter.toLowerCase();
      logs = logs.filter(
        (r) =>
          r.eventSource.includes(f) ||
          r.eventName.toLowerCase().includes(f)
      );
    }

    if (timeRange) {
      const [start, end] = (timeRange as string).split(",");
      logs = logs.filter((r) => r.eventTime >= start && r.eventTime <= end);
    }

    return { totalEvents: logs.length, events: logs };
  },
};

const flagAnomaliesTool: OpenClawTool = {
  name: "flag_anomalies",
  description: "Flag specific CloudTrail events as anomalous",
  parameters: {
    eventIds: { type: "array", description: "Array of eventID strings to flag", required: true },
    severity: { type: "string", description: "CRITICAL | HIGH | MEDIUM | LOW", required: true },
    reason: { type: "string", description: "Reason these events are anomalous", required: true },
  },
  async execute(params, context) {
    const ids = params.eventIds as string[];
    const flagged = context.cloudTrailLogs.filter((r) => ids.includes(r.eventID));
    return { flagged: flagged.length, severity: params.severity, reason: params.reason, events: flagged };
  },
};

const mapAttackPathTool: OpenClawTool = {
  name: "map_attack_path",
  description: "Build a chronological attack path from an ordered list of event IDs",
  parameters: {
    eventIds: { type: "array", description: "Ordered event IDs forming the attack chain", required: true },
  },
  async execute(params, context) {
    const ids = params.eventIds as string[];
    const events = ids
      .map((id) => context.cloudTrailLogs.find((r) => r.eventID === id))
      .filter(Boolean)
      .sort((a, b) => new Date(a!.eventTime).getTime() - new Date(b!.eventTime).getTime());

    return {
      pathLength: events.length,
      startTime: events[0]?.eventTime,
      endTime: events[events.length - 1]?.eventTime,
      path: events.map((e, i) => ({
        step: i + 1,
        eventId: e!.eventID,
        eventName: e!.eventName,
        timestamp: e!.eventTime,
        sourceIp: e!.sourceIPAddress,
        actor: e!.userIdentity.userName,
      })),
    };
  },
};

export function createDetectiveAgent(): OpenClawAgent {
  const agent: OpenClawAgent = {
    id: "detective",
    name: "Detective",
    color: COLOR,
    systemPrompt: SYSTEM_PROMPT,
    tools: [readLogsTool, flagAnomaliesTool, mapAttackPathTool],

    async process(context: InvestigationContext): Promise<AgentMessage> {
      updateAgentStatus("detective", "investigating");

      const msg = await invokeAgent(
        agent,
        context,
        [
          {
            role: "user",
            content:
              "Analyze the CloudTrail logs above. Identify all anomalies, reconstruct the attack path, and return your findings as JSON.",
          },
        ]
      );

      msg.type = "analysis";
      recordTaskCompletion("detective");
      updateAgentStatus("detective", "waiting");
      return msg;
    },
  };
  return agent;
}
