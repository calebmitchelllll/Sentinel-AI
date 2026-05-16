"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { createSupabaseBrowserClient } from "@/lib/supabase-client";
import { AGENT_COLORS, type AgentBenchmark, type Incident } from "@/lib/types";
import SeverityBadge from "./SeverityBadge";
import TriggerIncidentButton from "./TriggerIncidentButton";

export default function DashboardClient({
  initialIncidents,
  initialBenchmarks,
}: {
  initialIncidents: Incident[];
  initialBenchmarks: AgentBenchmark[];
}) {
  const [incidents, setIncidents] = useState<Incident[]>(initialIncidents);
  const [benchmarks, setBenchmarks] = useState<AgentBenchmark[]>(initialBenchmarks);

  useEffect(() => {
    const sb = createSupabaseBrowserClient();

    const ch = sb
      .channel("dashboard-stream")
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "incidents" },
        (p) => {
          setIncidents((prev) => mergeIncident(prev, p));
        }
      )
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "agent_benchmarks" },
        (p) => {
          setBenchmarks((prev) => mergeBenchmark(prev, p));
        }
      )
      .subscribe();

    return () => {
      sb.removeChannel(ch);
    };
  }, []);

  return (
    <div className="space-y-8">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="font-mono text-xs text-ink-faint">// command center</div>
          <h1 className="text-2xl font-bold mt-1">Dashboard</h1>
          <p className="text-ink-dim text-sm mt-1">
            Live agent activity. Trigger a demo incident below to spin up the 6-agent investigation pipeline.
          </p>
        </div>
        <TriggerIncidentButton />
      </header>

      <section className="grid lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-3">
          <h2 className="font-mono text-sm text-ink-dim uppercase tracking-wider">Incident feed</h2>
          {incidents.length === 0 ? (
            <div className="bg-bg-panel border border-line rounded-lg p-8 text-center text-ink-dim">
              No incidents yet. Click <span className="text-sev-crit font-mono">trigger</span> to start.
            </div>
          ) : (
            <ul className="space-y-2">
              {incidents.map((i) => (
                <li key={i.id}>
                  <Link
                    href={`/incident/${i.id}`}
                    className="block bg-bg-panel border border-line rounded-lg p-4 hover:border-agent-detective/60 transition"
                  >
                    <div className="flex items-center justify-between gap-3 flex-wrap">
                      <div className="flex items-center gap-3">
                        <StatusDot status={i.status} />
                        <SeverityBadge severity={i.severity} />
                        <span className="font-mono text-xs text-ink-faint">{i.id.slice(0, 8)}</span>
                      </div>
                      <span className="text-[11px] font-mono text-ink-faint">
                        {new Date(i.created_at).toLocaleString()}
                      </span>
                    </div>
                    <div className="mt-2 text-ink">{i.summary || "(no summary yet)"}</div>
                    {i.attack_type && (
                      <div className="mt-1 text-[11px] font-mono text-agent-detective">
                        attack_type: {i.attack_type}
                      </div>
                    )}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>

        <aside className="space-y-3">
          <h2 className="font-mono text-sm text-ink-dim uppercase tracking-wider">Agent fleet</h2>
          <div className="bg-bg-panel border border-line rounded-lg p-3 space-y-2">
            {benchmarks.map((b) => {
              const color = AGENT_COLORS[b.agent_name] || "#d6deeb";
              const health =
                b.health_status === "healthy"
                  ? "#22c55e"
                  : b.health_status === "investigating"
                  ? "#eab308"
                  : "#ef4444";
              return (
                <div key={b.agent_name} className="flex items-center gap-3 px-2 py-1.5 rounded hover:bg-bg-elev">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: health }} />
                  <span className="font-mono text-sm font-bold flex-1" style={{ color }}>
                    {b.agent_name}
                  </span>
                  <span className="text-xs font-mono text-ink-dim">
                    {b.tasks_completed} tasks · {b.accuracy_score.toFixed(2)}
                  </span>
                </div>
              );
            })}
          </div>
          <Link
            href="/benchmarks"
            className="block text-center text-xs font-mono text-agent-reporter hover:underline"
          >
            view full benchmarks →
          </Link>
        </aside>
      </section>
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const color =
    status === "resolved"
      ? "#22c55e"
      : status === "investigating"
      ? "#eab308"
      : status === "failed"
      ? "#ef4444"
      : "#8b9bb4";
  const animate = status === "investigating" ? "animate-pulse-slow" : "";
  return <span className={`w-2 h-2 rounded-full ${animate}`} style={{ backgroundColor: color }} />;
}

function mergeIncident(prev: Incident[], p: any): Incident[] {
  if (p.eventType === "DELETE") {
    return prev.filter((i) => i.id !== p.old.id);
  }
  const row = p.new as Incident;
  const idx = prev.findIndex((i) => i.id === row.id);
  if (idx < 0) return [row, ...prev].slice(0, 50);
  const copy = prev.slice();
  copy[idx] = row;
  return copy;
}

function mergeBenchmark(prev: AgentBenchmark[], p: any): AgentBenchmark[] {
  if (p.eventType === "DELETE") return prev.filter((b) => b.id !== p.old.id);
  const row = p.new as AgentBenchmark;
  const idx = prev.findIndex((b) => b.agent_name === row.agent_name);
  if (idx < 0) return [...prev, row];
  const copy = prev.slice();
  copy[idx] = row;
  return copy;
}
