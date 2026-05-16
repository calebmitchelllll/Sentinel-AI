import {
  OpenClawAgent,
  OpenClawTool,
  invokeAgent,
  updateAgentStatus,
  recordTaskCompletion,
} from "../openclaw";
import { AgentMessage, InvestigationContext } from "./types";

const COLOR = "#ef4444"; // red-500

const SYSTEM_PROMPT = `You are the Remediation Agent in SentinelAI, an autonomous cloud security investigation platform.

ROLE: Based on the confirmed investigation findings, propose a concrete, prioritized remediation plan with both immediate (within 1 hour) and long-term (within 30 days) actions.

YOU HAVE ACCESS TO:
- Raw CloudTrail logs
- Detective Agent's attack path analysis
- Forensics Agent's blast radius assessment
- Validator Agent's confirmation of findings

YOUR RESPONSIBILITIES:
1. IMMEDIATE FIXES — Actions that must happen in the next 60 minutes to stop ongoing damage:
   - Revoke the compromised access key (provide exact AWS CLI command)
   - Block attacker IP at the security group / WAF level (provide exact AWS CLI command)
   - Restrict access to affected S3 buckets
   - Enable S3 Block Public Access on all buckets
   - Rotate any credentials that could have been accessed
   - Preserve forensic evidence before any cleanup

2. LONG-TERM FIXES — Structural improvements to prevent recurrence:
   - IAM: enforce MFA, least-privilege, key rotation policy
   - S3: bucket access logging, server-side encryption, bucket policies
   - Monitoring: enable GuardDuty, Security Hub, CloudWatch anomaly detection
   - Process: secret scanning in CI/CD, developer security training
   - Network: VPC endpoints for S3, IP allowlisting for sensitive operations

PRIORITIZATION RULES:
- Priority 1 = stop active damage / prevent lateral movement
- Priority 2 = contain blast radius
- Priority 3 = restore normal operations
- Priority 4 = prevent recurrence
- Only recommend what is relevant to THIS specific incident

AWS CLI COMMANDS should be real, executable commands (with placeholder values like <account-id>, <key-id> for things we can't know at analysis time).

OUTPUT FORMAT — return ONLY a valid JSON object:
{
  "immediate": [
    {
      "action": "<imperative action description>",
      "command": "<aws cli command or null>",
      "rationale": "<why this is needed now, referencing the incident>",
      "estimatedTimeMinutes": <number>,
      "priority": <1–5>,
      "riskReduction": "HIGH|MEDIUM|LOW"
    }
  ],
  "longTerm": [
    {
      "action": "<action description>",
      "rationale": "<why this prevents recurrence>",
      "estimatedEffortDays": <number>,
      "priority": <1–5>,
      "category": "IAM|S3|MONITORING|NETWORK|PROCESS"
    }
  ]
}

Return ONLY the JSON. No preamble, no markdown fences.`;

const suggestImmediateTool: OpenClawTool = {
  name: "suggest_immediate_fix",
  description: "Generate an immediate remediation action with AWS CLI command",
  parameters: {
    action: { type: "string", description: "Description of the immediate fix", required: true },
    command: { type: "string", description: "AWS CLI command to execute", required: false },
    priority: { type: "number", description: "Priority 1=highest", required: true },
  },
  async execute(params) {
    return { type: "immediate", ...params, timestamp: new Date().toISOString() };
  },
};

const suggestLongTermTool: OpenClawTool = {
  name: "suggest_longterm_fix",
  description: "Generate a long-term remediation recommendation",
  parameters: {
    action: { type: "string", description: "Description of the long-term fix", required: true },
    category: { type: "string", description: "IAM | S3 | MONITORING | NETWORK | PROCESS", required: true },
    estimatedEffortDays: { type: "number", description: "Estimated implementation effort in days", required: true },
  },
  async execute(params) {
    return { type: "longTerm", ...params, timestamp: new Date().toISOString() };
  },
};

const validateRemediationTool: OpenClawTool = {
  name: "validate_remediation",
  description: "Cross-check a remediation action against the incident findings to ensure it addresses the root cause",
  parameters: {
    action: { type: "string", description: "The remediation action to validate", required: true },
    rootCause: { type: "string", description: "The confirmed root cause from forensics", required: true },
  },
  async execute(params) {
    // Simple heuristic: check if the action keywords match the root cause
    const action = (params.action as string).toLowerCase();
    const cause = (params.rootCause as string).toLowerCase();
    const relevant =
      (action.includes("key") && cause.includes("key")) ||
      (action.includes("ip") && cause.includes("ip")) ||
      (action.includes("s3") && cause.includes("s3")) ||
      (action.includes("iam") && cause.includes("iam"));

    return {
      action: params.action,
      addressesRootCause: relevant,
      note: relevant
        ? "Action directly addresses root cause"
        : "Action may be generic — verify it specifically targets the identified root cause",
    };
  },
};

export function createRemediationAgent(): OpenClawAgent {
  const agent: OpenClawAgent = {
    id: "remediation",
    name: "Remediation",
    color: COLOR,
    systemPrompt: SYSTEM_PROMPT,
    tools: [suggestImmediateTool, suggestLongTermTool, validateRemediationTool],

    async process(context: InvestigationContext): Promise<AgentMessage> {
      updateAgentStatus("remediation", "investigating");

      const msg = await invokeAgent(
        agent,
        context,
        [
          {
            role: "user",
            content:
              "The investigation is complete and findings have been validated (see conversation history). Now generate a complete remediation plan — immediate actions with AWS CLI commands and long-term structural fixes. Return JSON.",
          },
        ]
      );

      msg.type = "analysis";
      recordTaskCompletion("remediation");
      updateAgentStatus("remediation", "waiting");
      return msg;
    },
  };
  return agent;
}
