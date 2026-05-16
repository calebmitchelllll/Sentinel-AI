/**
 * Multi-agent orchestration engine.
 *
 * Drives the full investigation pipeline:
 *   Phase 1 — Detective analysis
 *   Phase 2 — Forensics deep dive
 *   Phase 3 — Validator challenges Detective + Forensics
 *   Phase 4 — Rebuttal round (Detective + Forensics respond)
 *   Phase 5 — Remediation proposals
 *   Phase 6 — Validator validates remediation
 *   Phase 7 — Reporter generates final incident report
 *   Throughout — Meta Agent monitors after each phase
 */

import {
  registerAgent,
  initAgentHealth,
  getAllAgentHealth,
  clearRegistry,
  onAgentMessage,
  invokeAgent,
  updateAgentStatus,
} from "./openclaw";
import { createDetectiveAgent } from "./agents/detective";
import { createForensicsAgent } from "./agents/forensics";
import { createRemediationAgent } from "./agents/remediation";
import { createValidatorAgent } from "./agents/validator";
import { createReporterAgent } from "./agents/reporter";
import { reportToMarkdown } from "./agents/reporter";
import { createMetaAgent } from "./agents/metaAgent";
import {
  AgentMessage,
  AgentState,
  CloudTrailLogs,
  IncidentReport,
  InvestigationContext,
  Severity,
} from "./agents/types";
import {
  saveIncidentToSupabase,
  saveIncidentReport,
  saveAgentMessage,
  appendLivingDoc,
  saveAgentBenchmarks,
} from "./supabase";

// ─── Public interface ─────────────────────────────────────────────────────────

export interface OrchestrationOptions {
  /** Called with each new agent message as the investigation progresses */
  onMessage?: (msg: AgentMessage) => void;
  /** Called when an agent status changes (for live UI indicators) */
  onStatusChange?: (agentId: string, status: string) => void;
  /** Persist messages and report to Supabase (requires env vars) */
  persist?: boolean;
}

export interface OrchestrationResult {
  incidentId: string;
  messages: AgentMessage[];
  report: IncidentReport | null;
  reportMarkdown: string;
  agentStates: AgentState[];
  durationMs: number;
  overallSeverity: Severity;
}

// ─── Main entry point ─────────────────────────────────────────────────────────

export async function runInvestigation(
  logs: CloudTrailLogs,
  options: OrchestrationOptions = {}
): Promise<OrchestrationResult> {
  const startTime = Date.now();
  const incidentId = crypto.randomUUID();
  const allMessages: AgentMessage[] = [];

  // Bootstrap: register all agents and initialise health state
  clearRegistry();
  const agents = [
    createDetectiveAgent(),
    createForensicsAgent(),
    createRemediationAgent(),
    createValidatorAgent(),
    createReporterAgent(),
    createMetaAgent(),
  ];
  for (const a of agents) {
    registerAgent(a);
    initAgentHealth(a.id, a.name, a.color);
  }

  // Strip internal _comment fields from the demo JSON before feeding to agents
  const cleanLogs = logs.Records.map(({ _comment: _, ...rest }) => rest);

  const context: InvestigationContext = {
    incidentId,
    cloudTrailLogs: cleanLogs,
    conversationHistory: allMessages,
    startTime: new Date().toISOString(),
  };

  // Wire up broadcast listener so options.onMessage fires for every message
  const unsub = onAgentMessage(async (msg) => {
    options.onMessage?.(msg);
    if (options.persist) {
      try { await saveAgentMessage(incidentId, msg); } catch { /* non-fatal */ }
    }
  });

  async function collect(msg: AgentMessage): Promise<void> {
    allMessages.push(msg);
    context.conversationHistory = [...allMessages];
  }

  try {
    const detective   = agents.find((a) => a.id === "detective")!;
    const forensics   = agents.find((a) => a.id === "forensics")!;
    const validator   = agents.find((a) => a.id === "validator")!;
    const remediation = agents.find((a) => a.id === "remediation")!;
    const reporter    = agents.find((a) => a.id === "reporter")!;
    const meta        = agents.find((a) => a.id === "meta")!;

    // ── Phase 1: Detective analysis ──────────────────────────────────────────
    console.log("[orchestrator] Phase 1: Detective");
    const detectiveMsg = await detective.process(context);
    await collect(detectiveMsg);
    console.log("[orchestrator] Phase 1 done, content length:", detectiveMsg.content.length);

    // Meta monitors after Phase 1
    console.log("[orchestrator] Meta check 1");
    await collect(await runMetaCheck(meta, context));

    // ── Phase 2: Forensics deep dive ─────────────────────────────────────────
    console.log("[orchestrator] Phase 2: Forensics");
    const forensicsMsg = await forensics.process(context);
    await collect(forensicsMsg);
    console.log("[orchestrator] Phase 2 done");

    // Meta monitors after Phase 2
    console.log("[orchestrator] Meta check 2");
    await collect(await runMetaCheck(meta, context));

    // ── Phase 3: Validator challenges both ───────────────────────────────────
    console.log("[orchestrator] Phase 3: Validator");
    const validationMsg = await validator.process(context);
    validationMsg.type = "challenge";
    await collect(validationMsg);
    console.log("[orchestrator] Phase 3 done");

    // ── Phase 4: Rebuttal round ──────────────────────────────────────────────
    console.log("[orchestrator] Phase 4: Rebuttals");
    const detectiveRebuttal = await runRebuttal(detective, context, validationMsg);
    await collect(detectiveRebuttal);

    const forensicsRebuttal = await runRebuttal(forensics, context, validationMsg);
    await collect(forensicsRebuttal);
    console.log("[orchestrator] Phase 4 done");

    // Meta monitors after debate
    console.log("[orchestrator] Meta check 3");
    await collect(await runMetaCheck(meta, context));

    // ── Phase 5: Remediation ─────────────────────────────────────────────────
    console.log("[orchestrator] Phase 5: Remediation");
    const remediationMsg = await remediation.process(context);
    await collect(remediationMsg);
    console.log("[orchestrator] Phase 5 done");

    // ── Phase 6: Validator validates remediation ──────────────────────────────
    console.log("[orchestrator] Phase 6: Validator → Remediation");
    const remValMsg = await validator.process(context);
    remValMsg.type = "challenge";
    remValMsg.targetAgentId = "remediation";
    await collect(remValMsg);
    console.log("[orchestrator] Phase 6 done");

    // ── Phase 7: Reporter synthesises everything ──────────────────────────────
    console.log("[orchestrator] Phase 7: Reporter");
    const reportMsg = await reporter.process(context);
    reportMsg.type = "report";
    await collect(reportMsg);
    console.log("[orchestrator] Phase 7 done, report length:", reportMsg.content.length);

    // Final meta check
    console.log("[orchestrator] Final meta check");
    await collect(await runMetaCheck(meta, context));
    console.log("[orchestrator] Pipeline complete");

    // ── Parse final report ────────────────────────────────────────────────────
    let report: IncidentReport | null = null;
    let reportMarkdown = "";
    try {
      const extractedJson = extractJSON(reportMsg.content);
      report = JSON.parse(extractedJson);
      report!.incidentId = incidentId;
      // Normalize severity to uppercase regardless of model output casing
      if (report!.severity) {
        report!.severity = (report!.severity as string).toUpperCase() as Severity;
      }
      reportMarkdown = reportToMarkdown(extractedJson, incidentId);
    } catch {
      reportMarkdown = `# Incident ${incidentId}\n\nReport parsing failed — raw agent output:\n\n${reportMsg.content}`;
    }

    const agentStates = getAllAgentHealth();
    const overallSeverity = (report?.severity ?? detectOverallSeverity(allMessages)) as Severity;

    // ── Persist to Supabase ───────────────────────────────────────────────────
    if (options.persist && report) {
      try {
        await saveIncidentToSupabase(incidentId, report, allMessages, Date.now() - startTime);
        await saveIncidentReport(incidentId, report, reportMarkdown);
        await appendLivingDoc(incidentId, reportMarkdown, report.tags ?? [], {
          title: report.executiveSummary?.slice(0, 120) ?? `Incident ${incidentId}`,
          severity: report.severity,
          attack_type: report.tags?.[0] ?? null,
        });
        await saveAgentBenchmarks(agentStates);
      } catch (err) {
        console.error("Supabase persist error:", err);
      }
    }

    return {
      incidentId,
      messages: allMessages,
      report,
      reportMarkdown,
      agentStates,
      durationMs: Date.now() - startTime,
      overallSeverity,
    };
  } finally {
    unsub();
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function runMetaCheck(
  metaAgent: ReturnType<typeof createMetaAgent>,
  context: InvestigationContext
): Promise<AgentMessage> {
  const msg = await metaAgent.process(context);
  // Upgrade severity if the meta agent found issues
  try {
    const health = JSON.parse(extractJSON(msg.content));
    const hasCompromised = health.checkedAgents?.some(
      (a: { status: string }) => a.status === "COMPROMISED" || a.status === "ALERT"
    );
    msg.severity = hasCompromised ? "HIGH" : "INFO";
  } catch { /* non-fatal */ }
  return msg;
}

async function runRebuttal(
  agent: ReturnType<typeof createDetectiveAgent | typeof createForensicsAgent>,
  context: InvestigationContext,
  challengeMsg: AgentMessage
): Promise<AgentMessage> {
  updateAgentStatus(agent.id, "investigating");

  const rebuttalPrompt = `The Validator Agent has challenged some of your findings (see the challenge in the conversation history above). Review each challenge and respond:
- For challenges you ACCEPT: acknowledge the correction and revise your finding
- For challenges you REJECT: provide additional specific evidence from the logs to defend your position
- Be precise and cite eventIDs, timestamps, and log fields

Return your response as plain text (not JSON). Be concise.`;

  const msg = await invokeAgent(agent, context, [
    { role: "user", content: rebuttalPrompt },
  ]);

  msg.type = "rebuttal";
  msg.targetAgentId = "validator";
  return msg;
}

/** Pull the first JSON object or array out of a string that may have surrounding text */
export function extractJSON(text: string): string {
  const start = text.search(/[{[]/);
  if (start === -1) return text;

  let depth = 0;
  let inString = false;
  let escape = false;

  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (escape) { escape = false; continue; }
    if (c === "\\" && inString) { escape = true; continue; }
    if (c === '"') { inString = !inString; continue; }
    if (inString) continue;
    if (c === "{" || c === "[") depth++;
    if (c === "}" || c === "]") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return text.slice(start);
}

function detectOverallSeverity(messages: AgentMessage[]): string {
  for (const msg of messages) {
    if (msg.content.includes('"overallSeverity":"CRITICAL"') ||
        msg.content.includes('"severity":"CRITICAL"')) {
      return "CRITICAL";
    }
  }
  return "HIGH";
}
