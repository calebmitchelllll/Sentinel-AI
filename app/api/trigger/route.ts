import { NextResponse } from "next/server";
import { createSupabaseServerClient, createSupabaseServiceClient } from "@/lib/supabase-server";

export const runtime = "nodejs";

export async function POST() {
  const supabase = createSupabaseServerClient();
  const {
    data: { session },
  } = await supabase.auth.getSession();
  if (!session) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }

  const service = createSupabaseServiceClient();
  const { data, error } = await service
    .from("incidents")
    .insert({
      status: "investigating",
      severity: null,
      summary: "Stolen developer AWS key + privilege escalation + S3 exfiltration (in progress)",
      attack_type: "credential-theft-privesc-exfiltration",
      triggered_by: session.user.id,
    })
    .select()
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ incidentId: data.id });
}
