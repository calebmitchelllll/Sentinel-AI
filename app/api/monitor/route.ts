/**
 * GET /api/monitor
 * Returns live agent health, benchmark scores, and jailbreak attempt counts.
 * The Meta Agent runs in the background and calls this endpoint to push updates.
 *
 * POST /api/monitor
 * Accepts a health report from the Meta Security Agent and stores it.
 * Also handles manual kill/restart commands for compromised agents.
 */

import { NextRequest, NextResponse } from "next/server";
import {
  getAllAgentHealth,
  getAgentHealth,
  terminateAgent,
  restartAgent,
} from "@/lib/openclaw";
import { AgentId } from "@/lib/agents/types";
import { createDetectiveAgent } from "@/lib/agents/detective";
import { createForensicsAgent } from "@/lib/agents/forensics";
import { createRemediationAgent } from "@/lib/agents/remediation";
import { createValidatorAgent } from "@/lib/agents/validator";
import { createReporterAgent } from "@/lib/agents/reporter";
import { createMetaAgent } from "@/lib/agents/metaAgent";

export const runtime = "nodejs";

export async function GET() {
  const agents = getAllAgentHealth();
  const totalJailbreakAttempts = agents.reduce(
    (sum, a) => sum + a.jailbreakAttempts, 0
  );
  const compromisedAgents = agents.filter((a) => a.status === "compromised");

  return NextResponse.json({
    agents,
    summary: {
      totalAgents: agents.length,
      healthyCount: agents.filter((a) => a.status === "idle" || a.status === "investigating" || a.status === "waiting").length,
      compromisedCount: compromisedAgents.length,
      totalJailbreakAttempts,
      averageBenchmarkScore: agents.length
        ? Math.round(agents.reduce((s, a) => s + a.benchmarkScore, 0) / agents.length)
        : 0,
    },
    timestamp: new Date().toISOString(),
  });
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();

    // Manual override: kill or restart a specific agent
    if (body.action === "kill" && body.agentId) {
      const id = body.agentId as AgentId;
      const state = getAgentHealth(id);
      if (!state) {
        return NextResponse.json({ error: `Agent ${id} not found` }, { status: 404 });
      }
      terminateAgent(id);
      return NextResponse.json({ action: "terminated", agentId: id, timestamp: new Date().toISOString() });
    }

    if (body.action === "restart" && body.agentId) {
      const id = body.agentId as AgentId;
      const factories = {
        detective:   createDetectiveAgent,
        forensics:   createForensicsAgent,
        remediation: createRemediationAgent,
        validator:   createValidatorAgent,
        reporter:    createReporterAgent,
        meta:        createMetaAgent,
      } as Record<AgentId, () => ReturnType<typeof createDetectiveAgent>>;

      const factory = factories[id];
      if (!factory) {
        return NextResponse.json({ error: `Unknown agent ID: ${id}` }, { status: 400 });
      }
      restartAgent(id, factory);
      return NextResponse.json({ action: "restarted", agentId: id, timestamp: new Date().toISOString() });
    }

    // Health report push from Meta Agent
    if (body.healthReport) {
      // In a real deployment, persist this to Supabase agent_benchmarks
      // For now, log it and return acknowledgement
      console.log("[/api/monitor] Health report received:", body.healthReport);
      return NextResponse.json({ received: true, timestamp: new Date().toISOString() });
    }

    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal server error" },
      { status: 500 }
    );
  }
}
