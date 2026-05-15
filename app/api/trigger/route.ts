/**
 * POST /api/trigger
 * Loads the demo CloudTrail dataset and kicks off the full multi-agent investigation.
 * Streams agent messages as newline-delimited JSON (NDJSON) for real-time UI updates.
 */

import { NextRequest } from "next/server";
import { runInvestigation } from "@/lib/agentOrchestrator";
import { CloudTrailLogs } from "@/lib/agents/types";
import demoLogs from "@/data/cloudtrail-demo.json";

export const runtime = "nodejs";
export const maxDuration = 300; // 5 min — investigation takes time

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const persist = body.persist === true;

  // Allow the caller to supply custom logs; fall back to the demo dataset
  const logs: CloudTrailLogs = body.logs ?? (demoLogs as unknown as CloudTrailLogs);

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      function send(data: unknown) {
        controller.enqueue(encoder.encode(JSON.stringify(data) + "\n"));
      }

      try {
        send({ type: "start", incidentId: "pending", timestamp: new Date().toISOString() });

        const result = await runInvestigation(logs, {
          persist,
          onMessage(msg) {
            send({ type: "message", payload: msg });
          },
          onStatusChange(agentId, status) {
            send({ type: "status_change", agentId, status });
          },
        });

        send({
          type: "complete",
          incidentId: result.incidentId,
          severity: result.overallSeverity,
          durationMs: result.durationMs,
          agentStates: result.agentStates,
          report: result.report,
        });
      } catch (err) {
        send({
          type: "error",
          message: err instanceof Error ? err.message : "Investigation failed",
        });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "application/x-ndjson",
      "Transfer-Encoding": "chunked",
      "Cache-Control": "no-cache",
      "X-Accel-Buffering": "no",
    },
  });
}
