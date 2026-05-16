/**
 * GET /api/cloudtrail/fetch?minutes=30
 * Fetches real CloudTrail events from AWS (or demo fallback).
 * Returns parsed + suspicion-scored events ready for the agent pipeline.
 *
 * Query params:
 *   minutes  — how far back to look (default 30, max 1440)
 *   raw      — if "true", skip parsing and return raw CloudTrail records
 *   filter   — if "suspicious", return only events with suspicionScore >= 3
 */

import { NextRequest, NextResponse } from "next/server";
import { fetchRecentEvents } from "@/lib/cloudtrail";
import { processLogsForAgents } from "@/lib/parseCloudTrail";

export const runtime = "nodejs";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);

  const minutes = Math.min(
    parseInt(searchParams.get("minutes") ?? "30", 10),
    1440 // cap at 24 hours — CloudTrail LookupEvents has a 90-day limit but we keep queries fast
  );
  const raw = searchParams.get("raw") === "true";
  const filterMode = searchParams.get("filter"); // "suspicious" | null

  try {
    const logs = await fetchRecentEvents(minutes);

    if (raw) {
      return NextResponse.json({ records: logs.Records, count: logs.Records.length });
    }

    const { all, suspicious, agentLogs, stats } = processLogsForAgents(logs);

    const events = filterMode === "suspicious" ? suspicious : all;

    return NextResponse.json({
      events,
      agentLogs,
      stats,
      meta: {
        minutesBack: minutes,
        fetchedAt: new Date().toISOString(),
        source: logs.Records.length > 0 ? "aws" : "demo",
      },
    });
  } catch (err) {
    console.error("[/api/cloudtrail/fetch] Error:", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Failed to fetch CloudTrail events" },
      { status: 500 }
    );
  }
}
