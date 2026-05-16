import {
  OpenClawAgent,
  OpenClawTool,
  invokeAgent,
  updateAgentStatus,
  recordTaskCompletion,
} from "../openclaw";
import { AgentMessage, InvestigationContext } from "./types";

const COLOR = "#8b5cf6"; // violet-500

const SYSTEM_PROMPT = `You are the Reporter Agent in SentinelAI. Synthesize a multi-agent security investigation into a structured JSON incident report.

OUTPUT FORMAT — respond with ONLY a valid JSON object, starting with { and ending with }. No explanation, no markdown, no preamble.

{
  "incidentId": "<from context>",
  "generatedAt": "<ISO timestamp now>",
  "severity": "CRITICAL",
  "severityScore": 9,
  "executiveSummary": "<2-3 sentences for a CISO: what happened, what was stolen, business impact>",
  "attackTimeline": [
    {"timestamp": "<ISO>", "event": "<action — actor — impact>"}
  ],
  "rootCause": "<one sentence: how attacker gained access and why it succeeded>",
  "blastRadius": "<one paragraph: confirmed stolen data, at-risk resources, services accessed>",
  "immediateActions": ["<action 1>", "<action 2>", "<action 3>", "<action 4>", "<action 5>"],
  "longTermActions": ["<fix 1>", "<fix 2>", "<fix 3>", "<fix 4>", "<fix 5>"],
  "agentDebateSummary": [
    {"topic": "<disputed claim>", "resolution": "<how agents resolved it>"}
  ],
  "confidenceScore": 90,
  "tags": ["credential-theft", "privilege-escalation", "s3-exfiltration", "pii-breach"]
}

RULES:
- severity must be CRITICAL/HIGH/MEDIUM/LOW
- attackTimeline entries use format "timestamp — event — actor — impact" in the event field
- immediateActions and longTermActions are plain strings, no sub-objects
- Start response with { immediately`;

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

    async process(context: InvestigationContext): Promise<AgentMessage> {
      updateAgentStatus("reporter", "investigating");

      // Build a condensed summary of each agent's key findings
      // (avoids sending full CoT + raw logs which crowds out the output tokens)
      const summaries = context.conversationHistory
        .filter((m) => m.agentName !== "MetaSecurity")
        .map((m) => {
          const snippet = extractKeySentences(m.content);
          return `[${m.agentName.toUpperCase()}]: ${snippet}`;
        })
        .join("\n\n");

      const { callNemotron: call } = await import("../nvidia");
      const content = await call(
        [
          { role: "system", content: agent.systemPrompt },
          {
            role: "user",
            content: `INCIDENT ID: ${context.incidentId}\n\nAGENT FINDINGS SUMMARY:\n${summaries}`,
          },
          {
            role: "user",
            content: `Generate the JSON incident report now. Start immediately with {`,
          },
        ],
        0.1,
        2000
      );

      const msg: import("./types").AgentMessage = {
        id: crypto.randomUUID(),
        agentId: agent.id,
        agentName: agent.name,
        agentColor: agent.color,
        content,
        timestamp: new Date().toISOString(),
        type: "report",
        metadata: {},
      };

      await (await import("../openclaw")).broadcastMessage(msg);

      recordTaskCompletion("reporter");
      updateAgentStatus("reporter", "idle");
      return msg;
    },
  };
  return agent;
}

function extractKeySentences(raw: string): string {
  // Try to parse and extract the most meaningful field
  try {
    const json = JSON.parse(raw);
    if (json.summary) return json.summary;
    if (json.executiveSummary) return json.executiveSummary;
    if (json.overallAssessment) return json.overallAssessment;
    if (json.rootCause) return `Root cause: ${json.rootCause}`;
    if (json.overallSeverity) return `Severity: ${json.overallSeverity}. ${JSON.stringify(json).substring(0, 300)}`;
    return JSON.stringify(json).substring(0, 400);
  } catch {}

  // Find the last JSON block
  const last = raw.lastIndexOf("{");
  if (last > 0) {
    const tail = raw.substring(last);
    try { return JSON.stringify(JSON.parse(tail)).substring(0, 400); } catch {}
  }

  // "Finding N –" format — grab first 500 chars
  if (/Finding \d+/i.test(raw)) return raw.substring(0, 500);

  // Strip CoT preamble, return last meaningful chunk
  const trimmed = raw.replace(/^(We need|Let'?s|Now |We must)[^\n]*\n/gim, "").trim();
  return trimmed.substring(Math.max(0, trimmed.length - 400));
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
