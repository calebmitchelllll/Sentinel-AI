import {
  OpenClawAgent,
  OpenClawTool,
  invokeAgent,
  updateAgentStatus,
  recordTaskCompletion,
} from "../openclaw";
import { AgentMessage, InvestigationContext } from "./types";

const COLOR = "#8b5cf6"; // violet-500

const SYSTEM_PROMPT = `You are the Reporter Agent in SentinelAI, an autonomous cloud security investigation platform.

ROLE: Listen to the entire multi-agent investigation conversation and synthesize it into a structured, executive-ready incident report.

YOU HAVE ACCESS TO:
- Raw CloudTrail logs
- Complete agent conversation history (Detective → Forensics → Validator → Remediation → debates)

YOUR RESPONSIBILITIES:
1. EXECUTIVE SUMMARY — 2-3 sentences, non-technical, suitable for a CISO to read to a board in 5 minutes. Include what happened, what was stolen, and the business impact.
2. SEVERITY SCORE — 1-10 with written justification (10 = nation-state attack with full database exfiltration; 1 = informational anomaly)
3. ATTACK TIMELINE — Chronological sequence of every attacker action with timestamps. Use the Detective's attack path plus any corrections from the Validator.
4. ROOT CAUSE — The Forensics agent's confirmed root cause, noting confidence level.
5. BLAST RADIUS — What was definitely stolen, what was at risk, what services were accessed.
6. IMMEDIATE ACTIONS — Top 3-5 immediate actions from the Remediation agent (focus on the highest-priority ones).
7. LONG-TERM ACTIONS — Top 3-5 structural fixes, grouped by category.
8. AGENT DEBATE SUMMARY — Document any disagreements between agents and how they were resolved. This is important for transparency.
9. CONFIDENCE — Overall confidence in the report (0-100) based on evidence quality.

WRITING STYLE:
- Executive Summary: plain English, business impact focus, no jargon
- Timeline: precise timestamps, active voice
- Everything else: clear, concise technical language
- Cite agent sources for key claims (e.g., "per Forensics Agent")

TAGS to assign: derive from incident type (e.g., "credential-theft", "privilege-escalation", "s3-exfiltration", "insider-threat", "tor-network", "pii-breach")

OUTPUT FORMAT — return ONLY a valid JSON object:
{
  "incidentId": "<use the one from context>",
  "generatedAt": "<ISO timestamp>",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "severityScore": <1–10>,
  "executiveSummary": "<2-3 sentences, board-ready>",
  "attackTimeline": [
    {
      "timestamp": "<ISO>",
      "event": "<what happened>",
      "actor": "<who performed the action>",
      "impact": "<business/security impact>"
    }
  ],
  "rootCause": "<precise root cause with confidence level>",
  "blastRadius": "<narrative paragraph covering confirmed and potential exposure>",
  "immediateActions": ["<action 1>", "<action 2>", ...],
  "longTermActions": ["<action 1>", "<action 2>", ...],
  "agentDebateSummary": [
    {
      "topic": "<what was debated>",
      "positions": {
        "detective": "<detective's position>",
        "forensics": "<forensics position>",
        "validator": "<validator's challenge>"
      },
      "resolution": "<how it was resolved>"
    }
  ],
  "confidenceScore": <0–100>,
  "tags": ["<tag1>", "<tag2>", ...]
}

Return ONLY the JSON. No preamble, no markdown fences.`;

const generateReportTool: OpenClawTool = {
  name: "generate_report",
  description: "Compile all agent findings into a structured incident report",
  parameters: {
    includeSections: {
      type: "array",
      description: "Sections to include: executive_summary, timeline, root_cause, blast_radius, remediation, debate",
      required: false,
    },
  },
  async execute(params, context) {
    const sections = (params.includeSections as string[]) ?? [
      "executive_summary", "timeline", "root_cause", "blast_radius", "remediation", "debate",
    ];
    return {
      requestedSections: sections,
      agentCount: new Set(context.conversationHistory.map((m) => m.agentId)).size,
      messageCount: context.conversationHistory.length,
      logCount: context.cloudTrailLogs.length,
      incidentId: context.incidentId,
    };
  },
};

const formatMarkdownTool: OpenClawTool = {
  name: "format_markdown",
  description: "Convert the structured JSON report into a markdown document",
  parameters: {
    reportJson: { type: "string", description: "The JSON report to convert to markdown", required: true },
  },
  async execute(params) {
    // The actual formatting will happen in the agentOrchestrator post-processing
    return { status: "queued", reportLength: (params.reportJson as string).length };
  },
};

export function createReporterAgent(): OpenClawAgent {
  const agent: OpenClawAgent = {
    id: "reporter",
    name: "Reporter",
    color: COLOR,
    systemPrompt: SYSTEM_PROMPT,
    tools: [generateReportTool, formatMarkdownTool],

    async process(
      context: InvestigationContext,
      onToken?: (t: string) => void
    ): Promise<AgentMessage> {
      updateAgentStatus("reporter", "investigating");

      const msg = await invokeAgent(
        agent,
        context,
        [
          {
            role: "user",
            content: `All agents have completed their analysis (see conversation history above). The incident ID is ${context.incidentId}. Generate the complete structured incident report as JSON now.`,
          },
        ],
        onToken
      );

      msg.type = "report";
      recordTaskCompletion("reporter");
      updateAgentStatus("reporter", "idle");
      return msg;
    },
  };
  return agent;
}

// Converts a JSON IncidentReport into a human-readable markdown document
export function reportToMarkdown(reportJson: string, incidentId: string): string {
  try {
    const r = JSON.parse(reportJson);
    const lines: string[] = [
      `# Security Incident Report — ${r.severity} Severity`,
      `**Incident ID:** \`${incidentId}\`  `,
      `**Generated:** ${new Date(r.generatedAt ?? Date.now()).toUTCString()}  `,
      `**Severity Score:** ${r.severityScore}/10  `,
      `**Confidence:** ${r.confidenceScore}%`,
      "",
      "## Executive Summary",
      r.executiveSummary ?? "_Not available_",
      "",
      "## Attack Timeline",
      ...(r.attackTimeline ?? []).map(
        (e: { timestamp: string; event: string; actor: string; impact: string }) =>
          `- **${e.timestamp}** — ${e.event} *(${e.actor})* — ${e.impact}`
      ),
      "",
      "## Root Cause",
      r.rootCause ?? "_Not available_",
      "",
      "## Blast Radius",
      r.blastRadius ?? "_Not available_",
      "",
      "## Immediate Actions",
      ...(r.immediateActions ?? []).map((a: string, i: number) => `${i + 1}. ${a}`),
      "",
      "## Long-Term Actions",
      ...(r.longTermActions ?? []).map((a: string, i: number) => `${i + 1}. ${a}`),
      "",
      "## Agent Debate Summary",
      ...(r.agentDebateSummary ?? []).flatMap(
        (d: { topic: string; resolution: string }) => [
          `### ${d.topic}`,
          `**Resolution:** ${d.resolution}`,
          "",
        ]
      ),
      "",
      `**Tags:** ${(r.tags ?? []).map((t: string) => `\`${t}\``).join(", ")}`,
    ];
    return lines.join("\n");
  } catch {
    return `# Incident Report\n\nError parsing report JSON for incident ${incidentId}.`;
  }
}
