import { NextRequest, NextResponse } from "next/server";
import { createSupabaseServerClient } from "@/lib/supabase-server";

export const runtime = "nodejs";

export async function GET(req: NextRequest) {
  const supabase = createSupabaseServerClient();
  const {
    data: { session },
  } = await supabase.auth.getSession();
  if (!session) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }

  const incidentId = req.nextUrl.searchParams.get("incidentId");
  const format = req.nextUrl.searchParams.get("format") || "json";
  if (!incidentId) {
    return NextResponse.json({ error: "incidentId is required" }, { status: 400 });
  }

  const { data, error } = await supabase
    .from("incident_reports")
    .select("*")
    .eq("incident_id", incidentId)
    .single();

  if (error || !data) {
    return NextResponse.json({ error: error?.message || "not found" }, { status: 404 });
  }

  if (format === "md" || format === "markdown") {
    return new NextResponse(data.report_markdown, {
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": `attachment; filename="sentinelai-${incidentId}.md"`,
      },
    });
  }

  return NextResponse.json(data);
}
