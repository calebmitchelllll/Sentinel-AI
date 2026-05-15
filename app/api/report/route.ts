/**
 * GET /api/report?incidentId=<id>
 * Fetch a stored incident report (requires Supabase).
 * Returns report JSON and markdown.
 *
 * GET /api/report?incidentId=<id>&format=markdown
 * Returns the report as a plain-text markdown response (for download).
 *
 * POST /api/report
 * Re-generate a report from existing agent messages (re-runs Reporter Agent only).
 */

import { NextRequest, NextResponse } from "next/server";
import { getIncident, getIncidentMessages } from "@/lib/supabase";
import { reportToMarkdown } from "@/lib/agents/reporter";
import { createReporterAgent } from "@/lib/agents/reporter";
import { invokeAgent } from "@/lib/openclaw";
import { InvestigationContext, CloudTrailRecord } from "@/lib/agents/types";

export const runtime = "nodejs";
export const maxDuration = 120;

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const incidentId = searchParams.get("incidentId");
  const format = searchParams.get("format");

  if (!incidentId) {
    return NextResponse.json({ error: "incidentId query parameter is required" }, { status: 400 });
  }

  try {
    const incident = await getIncident(incidentId);
    if (!incident) {
      return NextResponse.json({ error: "Incident not found" }, { status: 404 });
    }

    const markdown = reportToMarkdown(JSON.stringify(incident.report_json), incidentId);

    if (format === "markdown") {
      return new Response(markdown, {
        headers: {
          "Content-Type": "text/markdown",
          "Content-Disposition": `attachment; filename="incident-${incidentId}.md"`,
        },
      });
    }

    return NextResponse.json({
      incidentId,
      report: incident.report_json,
      markdown,
      createdAt: incident.created_at,
    });
  } catch (err) {
    console.error("[/api/report GET] Error:", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal server error" },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { incidentId } = body;

    if (!incidentId) {
      return NextResponse.json({ error: "incidentId is required" }, { status: 400 });
    }

    // Fetch stored messages and re-run the Reporter Agent
    const messages = await getIncidentMessages(incidentId);
    if (messages.length === 0) {
      return NextResponse.json({ error: "No messages found for this incident" }, { status: 404 });
    }

    const context: InvestigationContext = {
      incidentId,
      cloudTrailLogs: [] as CloudTrailRecord[],
      conversationHistory: messages,
      startTime: messages[0]?.timestamp ?? new Date().toISOString(),
    };

    const reporter = createReporterAgent();
    const reportMsg = await invokeAgent(reporter, context, [
      {
        role: "user",
        content: `Re-generate the incident report for incident ID ${incidentId} using the agent conversation history above. Return JSON.`,
      },
    ]);

    const markdown = reportToMarkdown(reportMsg.content, incidentId);

    return NextResponse.json({
      incidentId,
      reportRaw: reportMsg.content,
      markdown,
      regeneratedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error("[/api/report POST] Error:", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Internal server error" },
      { status: 500 }
    );
  }
}
