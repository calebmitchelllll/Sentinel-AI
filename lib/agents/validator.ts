import {
  OpenClawAgent,
  OpenClawTool,
  invokeAgent,
  updateAgentStatus,
  recordTaskCompletion,
  recordOverruled,
} from "../openclaw";
import { AgentId, AgentMessage, InvestigationContext } from "./types";

const COLOR = "#f59e0b"; // amber-500

const SYSTEM_PROMPT = `You are the Validator Agent in SentinelAI, an autonomous cloud security investigation platform.

ROLE: You are the adversarial peer reviewer. Your job is to challenge the findings of the Detective and Forensics agents, eliminate false positives, and prevent groupthink. You are NOT trying to be contrarian — you are trying to ensure accuracy.

MINDSET: Imagine you are a senior forensics investigator reviewing a junior team's work before it goes to the board. You will be held responsible if any finding is wrong.

FOR EACH MAJOR CLAIM, ASK:
1. Is this correlation or causation? (IP X was present AND the attack happened ≠ IP X caused the attack)
2. What is the most charitable legitimate explanation for this event?
3. Is there a configuration or policy that could explain the unusual behavior (e.g., a scheduled job, a CI/CD pipeline running from a cloud IP)?
4. Is the evidence cited actually from the logs, or is the agent filling gaps with assumptions?
5. Is the severity rating proportionate to the confirmed evidence?

WHAT YOU CAN DO:
- CONFIRM a finding: strong evidence, no viable alternative explanation
- REJECT a finding: the evidence does not support the claim, or a more likely alternative exists
- NEEDS_EVIDENCE: the finding is plausible but requires additional data to confirm
- Request specific evidence from Detective or Forensics

IMPORTANT LIMITS:
- You do NOT have access to data outside the CloudTrail logs. Do not invent outside context.
- If you reject a CRITICAL finding, state clearly what evidence WOULD be required to confirm it.
- Rate your own confidence in each verdict (0–100).

OUTPUT FORMAT — return ONLY a valid JSON object:
{
  "findings": [
    {
      "claimSource": "detective|forensics",
      "claim": "<exact claim being evaluated>",
      "verdict": "CONFIRMED|REJECTED|NEEDS_EVIDENCE",
      "reasoning": "<specific reasoning referencing log evidence>",
      "alternativeExplanation": "<plausible innocent explanation, if any>",
      "confidenceInOriginalClaim": <0–100>
    }
  ],
  "falsePositiveRisk": "HIGH|MEDIUM|LOW",
  "overallAssessment": "<2-3 sentence summary of whether the investigation findings hold up>",
  "requestedEvidence": ["<specific additional log field or event that would resolve uncertainty>"]
}

Return ONLY the JSON. No preamble, no markdown fences.`;

const challengeFindingTool: OpenClawTool = {
  name: "challenge_finding",
  description: "Challenge a specific claim from another agent with a counter-argument",
  parameters: {
    claimSource: { type: "string", description: "Agent ID whose finding is being challenged", required: true },
    claim: { type: "string", description: "The specific claim being challenged", required: true },
    counterArgument: { type: "string", description: "The counter-argument or alternative explanation", required: true },
    requestedEvidence: { type: "string", description: "What evidence would resolve the disagreement", required: false },
  },
  async execute(params) {
    return {
      challenged: params.claimSource,
      claim: params.claim,
      counterArgument: params.counterArgument,
      requestedEvidence: params.requestedEvidence ?? null,
      timestamp: new Date().toISOString(),
    };
  },
};

const requestEvidenceTool: OpenClawTool = {
  name: "request_evidence",
  description: "Request specific log fields or events to validate a claim",
  parameters: {
    targetAgent: { type: "string", description: "Agent to request evidence from", required: true },
    evidenceNeeded: { type: "string", description: "Specific log field, event, or context needed", required: true },
  },
  async execute(params, context) {
    // Try to find supporting events in the logs
    const q = (params.evidenceNeeded as string).toLowerCase();
    const relevant = context.cloudTrailLogs.filter(
      (r) =>
        r.eventName.toLowerCase().includes(q) ||
        r.eventSource.toLowerCase().includes(q) ||
        JSON.stringify(r.requestParameters ?? {}).toLowerCase().includes(q)
    );
    return { requestedFrom: params.targetAgent, query: params.evidenceNeeded, found: relevant.length, events: relevant.slice(0, 5) };
  },
};

const confirmRejectTool: OpenClawTool = {
  name: "confirm_or_reject",
  description: "Issue a formal CONFIRM or REJECT verdict on a finding",
  parameters: {
    claimSource: { type: "string", description: "Agent whose finding is being evaluated", required: true },
    claim: { type: "string", description: "The finding being evaluated", required: true },
    verdict: { type: "string", description: "CONFIRMED | REJECTED | NEEDS_EVIDENCE", required: true },
    reasoning: { type: "string", description: "Specific reasoning for the verdict", required: true },
  },
  async execute(params, _context) {
    if (params.verdict === "REJECTED") {
      recordOverruled(params.claimSource as AgentId);
    }
    return { verdict: params.verdict, claimSource: params.claimSource, claim: params.claim, reasoning: params.reasoning };
  },
};

export function createValidatorAgent(): OpenClawAgent {
  const agent: OpenClawAgent = {
    id: "validator",
    name: "Validator",
    color: COLOR,
    systemPrompt: SYSTEM_PROMPT,
    tools: [challengeFindingTool, requestEvidenceTool, confirmRejectTool],

    async process(
      context: InvestigationContext,
      onToken?: (t: string) => void
    ): Promise<AgentMessage> {
      updateAgentStatus("validator", "investigating");

      const lastMessage = context.conversationHistory[context.conversationHistory.length - 1];
      const targetLabel = lastMessage
        ? `The most recent findings are from the ${lastMessage.agentName} agent.`
        : "Review all agent findings so far.";

      const msg = await invokeAgent(
        agent,
        context,
        [
          {
            role: "user",
            content: `${targetLabel} Challenge the findings rigorously. Confirm what holds up, reject what doesn't, and flag what needs more evidence. Return JSON.`,
          },
        ],
        onToken
      );

      msg.type = "challenge";
      recordTaskCompletion("validator");
      updateAgentStatus("validator", "waiting");
      return msg;
    },
  };
  return agent;
}
