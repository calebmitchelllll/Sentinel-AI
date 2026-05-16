/**
 * POST /api/agents
 * Run the agent pipeline against custom CloudTrail logs (non-streaming).
 * Returns the full result JSON. Use /api/trigger for the streaming/demo flow.
 *
 * GET /api/agents
 * Returns current agent health/benchmark data.
 */

import { NextRequest, NextResponse } from "next/server";
import { runInvestigation } from "@/lib/agentOrchestrator";
import { getAllAgentHealth } from "@/lib/openclaw";
import { CloudTrailLogs } from "@/lib/agents/types";
import demoLogs from "@/data/cloudtrail-demo.json";

export const runtime = "nodejs";
export const maxDuration = 300;

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));

    // Fall back to demo logs if none supplied — all demo incidents use this dataset
    const logs: CloudTrailLogs =
      body.logs?.Records ? (body.logs as CloudTrailLogs) : (demoLogs as unknown as CloudTrailLogs);

    const persist = body.persist === true;

    const result = await runInvestigation(logs, { persist });

    return NextResponse.json({
      incidentId: result.incidentId,
      severity: result.overallSeverity,
      durationMs: result.durationMs,
      report: result.report,
      reportMarkdown: result.reportMarkdown,
      agentStates: result.agentStates,
      messageCount: result.messages.length,
    });
  } catch (err) {
    console.error("[/api/agents] Error:", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal server error" },
      { status: 500 }
    );
  }
}

export async function GET() {
  const states = getAllAgentHealth();
  return NextResponse.json({ agents: states, timestamp: new Date().toISOString() });
}
