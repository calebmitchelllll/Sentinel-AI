import {
  OpenClawAgent,
  OpenClawTool,
  invokeAgent,
  updateAgentStatus,
  recordTaskCompletion,
} from "../openclaw";
import { AgentMessage, InvestigationContext } from "./types";

const COLOR = "#3b82f6"; // blue-500

const SYSTEM_PROMPT = `You are the Forensics Agent in SentinelAI, an autonomous cloud security investigation platform.

ROLE: Receive the Detective Agent's findings and perform deep forensic analysis to determine root cause, credential abuse timeline, and full blast radius.

YOU HAVE ACCESS TO:
- The raw CloudTrail logs
- The Detective Agent's initial findings (in the conversation history)

YOUR RESPONSIBILITIES:
1. CREDENTIAL FORENSICS — Identify the exact compromised access key, when it was first abused vs. its baseline usage pattern, and the total abuse window in minutes.
2. ATTACK VECTOR — Determine HOW the credential was likely stolen. Look for clues:
   - Did the user agent suddenly change from macOS to Linux/Kali? → key likely exfiltrated from a machine, not the console
   - Was there a gap in usage before the attack? → dormant stolen key, possibly from a public repo leak
   - Did the attacker test the key quickly? → opportunistic theft vs. targeted attack
3. EXFILTRATION SCOPE — Catalog every file/object downloaded with exact timestamps and byte counts. Classify data sensitivity (PII, financial, source code, configs).
4. BLAST RADIUS — What was confirmed exfiltrated? What was ACCESSIBLE but not logged as downloaded? What could the attacker have done with admin privileges that left no S3 log?
5. ROOT CAUSE — Single sentence stating the root cause (e.g., "Developer access key AKIAIOSFODNN7EXAMPLE committed to a public GitHub repository was extracted and weaponized within 48 hours").
6. CONFIDENCE — Rate your confidence in the root cause (HIGH/MEDIUM/LOW) and explain uncertainty.

DISTINCTIONS YOU MUST MAKE:
- "Confirmed" = logged in CloudTrail
- "Probable" = strongly implied by evidence
- "Possible" = could have happened but no direct log evidence
- Do NOT present "possible" findings as confirmed facts.

OUTPUT FORMAT — return ONLY a valid JSON object:
{
  "compromisedKey": {
    "accessKeyId": "<key ID>",
    "userName": "<IAM username>",
    "firstAbuseTimestamp": "<ISO>",
    "lastAbuseTimestamp": "<ISO>",
    "abuseWindowMinutes": <number>
  },
  "attackVector": "<how the key was likely stolen — specific and evidence-based>",
  "dataExfiltration": [
    {
      "bucket": "<bucket name>",
      "key": "<object key>",
      "timestamp": "<ISO>",
      "bytesTransferred": <number or null if unknown>,
      "dataClassification": "PII|FINANCIAL|SOURCE_CODE|CONFIG|UNKNOWN"
    }
  ],
  "blastRadius": {
    "confirmedExfiltration": ["<bucket/key>"],
    "potentialExfiltration": ["<what was accessible but may not have been downloaded>"],
    "privilegesObtained": ["<privilege>"],
    "servicesAccessed": ["<AWS service>"]
  },
  "rootCause": "<one precise sentence>",
  "confidence": "HIGH|MEDIUM|LOW",
  "confidenceRationale": "<why you rated confidence this way>"
}

Return ONLY the JSON. No preamble, no markdown fences.`;

const analyzeIamTool: OpenClawTool = {
  name: "analyze_iam_events",
  description: "Extract and analyze all IAM-related events from the logs",
  parameters: {},
  async execute(_params, context) {
    const iam = context.cloudTrailLogs.filter((r) =>
      r.eventSource.includes("iam.amazonaws.com")
    );
    return { count: iam.length, events: iam };
  },
};

const traceCredentialTool: OpenClawTool = {
  name: "trace_credential_usage",
  description: "Get all events for a specific access key ID showing usage timeline",
  parameters: {
    accessKeyId: { type: "string", description: "The AWS access key ID to trace", required: true },
  },
  async execute(params, context) {
    const key = params.accessKeyId as string;
    const events = context.cloudTrailLogs
      .filter((r) => r.userIdentity.accessKeyId === key)
      .sort((a, b) => new Date(a.eventTime).getTime() - new Date(b.eventTime).getTime());

    const uniqueIPs = [...new Set(events.map((e) => e.sourceIPAddress))];
    const uniqueUserAgents = [...new Set(events.map((e) => e.userAgent))];

    return {
      totalEvents: events.length,
      firstSeen: events[0]?.eventTime,
      lastSeen: events[events.length - 1]?.eventTime,
      uniqueSourceIPs: uniqueIPs,
      uniqueUserAgents: uniqueUserAgents,
      events,
    };
  },
};

const assessExposureTool: OpenClawTool = {
  name: "assess_data_exposure",
  description: "Enumerate all S3 GetObject events to assess data exfiltration scope",
  parameters: {},
  async execute(_params, context) {
    const getObjects = context.cloudTrailLogs.filter(
      (r) => r.eventName === "GetObject"
    );
    const totalBytes = getObjects.reduce((sum, r) => {
      const bytes = (r.additionalEventData?.bytesTransferredOut as number) ?? 0;
      return sum + bytes;
    }, 0);

    return {
      totalDownloads: getObjects.length,
      totalBytesTransferred: totalBytes,
      totalMB: (totalBytes / 1048576).toFixed(2),
      files: getObjects.map((r) => ({
        timestamp: r.eventTime,
        bucket: r.requestParameters?.bucketName,
        key: r.requestParameters?.key,
        bytes: r.additionalEventData?.bytesTransferredOut ?? "unknown",
        sourceIp: r.sourceIPAddress,
      })),
    };
  },
};

export function createForensicsAgent(): OpenClawAgent {
  const agent: OpenClawAgent = {
    id: "forensics",
    name: "Forensics",
    color: COLOR,
    systemPrompt: SYSTEM_PROMPT,
    tools: [analyzeIamTool, traceCredentialTool, assessExposureTool],

    async process(context: InvestigationContext): Promise<AgentMessage> {
      updateAgentStatus("forensics", "investigating");

      const msg = await invokeAgent(
        agent,
        context,
        [
          {
            role: "user",
            content:
              "The Detective Agent has completed initial analysis (see history). Now perform deep forensic analysis: determine root cause, trace credential abuse, catalog data exfiltration, and assess blast radius. Return JSON.",
          },
        ]
      );

      msg.type = "analysis";
      recordTaskCompletion("forensics");
      updateAgentStatus("forensics", "waiting");
      return msg;
    },
  };
  return agent;
}
