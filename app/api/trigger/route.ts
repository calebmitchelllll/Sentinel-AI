/**
 * POST /api/trigger
 * Loads the demo CloudTrail dataset and kicks off the full multi-agent investigation.
 * Always returns NextResponse.json() — never a 500 or plain text — so the frontend
 * can rely on res.json() succeeding in every code path.
 */

import { NextRequest, NextResponse } from "next/server";
import { runInvestigation } from "@/lib/agentOrchestrator";
import { CloudTrailLogs } from "@/lib/agents/types";
import demoLogs from "@/data/cloudtrail-demo.json";

export const runtime = "nodejs";
export const maxDuration = 300; // 5 min — investigation takes time

export async function POST(req: NextRequest) {
  let body: Record<string, unknown> = {};
  try {
    body = await req.json();
  } catch {
    // no body or malformed JSON — that's fine, use defaults
  }

  const persist = body.persist === true;
  const logs: CloudTrailLogs =
    (body.logs as CloudTrailLogs) ?? (demoLogs as unknown as CloudTrailLogs);

  try {
    const result = await runInvestigation(logs, { persist });

    // report may be null if the reporter agent's JSON couldn't be parsed —
    // that's fine; still return incidentId so the frontend can navigate
    let report = result.report;
    if (report === null && result.reportMarkdown) {
      // Partial result: investigation ran but final JSON parse failed
      console.warn("[/api/trigger] Report JSON parse failed — returning partial result");
    }

    return NextResponse.json({
      incidentId: result.incidentId,
      severity: result.overallSeverity,
      durationMs: result.durationMs,
      agentStates: result.agentStates,
      report,
      partial: report === null,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error("[/api/trigger] Investigation failed:", message);
    if (err instanceof Error && err.stack) {
      console.error(err.stack);
    }

    // Return 200 with an error payload so res.json() always succeeds on the client
    return NextResponse.json({
      error: "Agent pipeline failed",
      details: message,
      fallback: true,
    });
  }
}
