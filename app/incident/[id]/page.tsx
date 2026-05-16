import Link from "next/link";
import { notFound } from "next/navigation";
import { requireSession, createSupabaseServerClient } from "@/lib/supabase-server";
import AgentChat from "@/components/AgentChat";
import IncidentReport from "@/components/IncidentReport";
import SeverityBadge from "@/components/SeverityBadge";
import type { Incident, IncidentReport as Report } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function IncidentPage({ params }: { params: { id: string } }) {
  await requireSession();
  const supabase = createSupabaseServerClient();

  const { data: incident } = await supabase
    .from("incidents")
    .select("*")
    .eq("id", params.id)
    .single();

  if (!incident) notFound();

  const { data: report } = await supabase
    .from("incident_reports")
    .select("*")
    .eq("incident_id", params.id)
    .maybeSingle();

  const i = incident as Incident;
  const r = (report as Report) || null;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <Link href="/dashboard" className="text-xs font-mono text-ink-dim hover:text-ink">
            ← back to dashboard
          </Link>
          <h1 className="text-2xl font-bold mt-1">Incident {i.id.slice(0, 8)}</h1>
          <div className="mt-2 flex items-center gap-3 flex-wrap">
            <SeverityBadge severity={i.severity} />
            <span className="text-xs font-mono text-ink-faint">{new Date(i.created_at).toLocaleString()}</span>
            <StatusPill status={i.status} />
          </div>
          {i.summary && <p className="text-ink-dim text-sm mt-2 max-w-3xl">{i.summary}</p>}
        </div>
      </div>

      {!r && (
        <section>
          <h2 className="font-mono text-sm text-ink-dim uppercase tracking-wider mb-2">
            Live agent investigation
          </h2>
          <AgentChat incidentId={i.id} />
        </section>
      )}

      {r && (
        <section>
          <IncidentReport report={r} />
        </section>
      )}
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const color =
    status === "resolved"
      ? "#22c55e"
      : status === "investigating"
      ? "#eab308"
      : "#ef4444";
  return (
    <span
      className="text-[10px] font-mono uppercase border rounded px-2 py-0.5"
      style={{ color, borderColor: color + "55", backgroundColor: color + "15" }}
    >
      {status}
    </span>
  );
}
