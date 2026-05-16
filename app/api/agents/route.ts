import { NextRequest, NextResponse } from "next/server";
import { promises as fs } from "node:fs";
import path from "node:path";
import { createSupabaseServerClient } from "@/lib/supabase-server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

let cachedLogs: { Records: unknown[]; _meta?: unknown } | null = null;

async function loadLogs() {
  if (cachedLogs) return cachedLogs;
  const p = path.join(process.cwd(), "data", "cloudtrail-demo.json");
  const raw = await fs.readFile(p, "utf-8");
  cachedLogs = JSON.parse(raw);
  return cachedLogs!;
}

export async function POST(req: NextRequest) {
  const supabase = createSupabaseServerClient();
  const {
    data: { session },
  } = await supabase.auth.getSession();
  if (!session) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }

  const body = (await req.json().catch(() => ({}))) as { incidentId?: string };
  if (!body.incidentId) {
    return NextResponse.json({ error: "incidentId is required" }, { status: 400 });
  }

  const logs = await loadLogs();
  const serviceUrl =
    process.env.NEMOCLAW_SERVICE_URL || "http://localhost:8000";

  // Proxy SSE from the Python orchestrator. We must use a streaming fetch.
  const upstream = await fetch(`${serviceUrl}/run-agents`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
    body: JSON.stringify({
      incidentId: body.incidentId,
      logs: logs.Records,
      meta: logs._meta,
    }),
  });

  if (!upstream.ok || !upstream.body) {
    const text = await upstream.text().catch(() => "");
    return NextResponse.json(
      { error: `nemoclaw runner returned ${upstream.status}`, detail: text },
      { status: 502 }
    );
  }

  return new Response(upstream.body, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
