"use client";

import { useEffect, useState } from "react";
import { createSupabaseBrowserClient } from "@/lib/supabase-client";
import { AGENT_COLORS, type AgentBenchmark } from "@/lib/types";

export default function AgentBenchmarkTable({ initial }: { initial: AgentBenchmark[] }) {
  const [rows, setRows] = useState<AgentBenchmark[]>(initial);

  useEffect(() => {
    const sb = createSupabaseBrowserClient();
    const channel = sb
      .channel("agent_benchmarks_changes")
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "agent_benchmarks" },
        (payload) => {
          setRows((prev) => {
            const updated = payload.new as AgentBenchmark;
            const idx = prev.findIndex((r) => r.agent_name === updated.agent_name);
            if (idx < 0) return [...prev, updated].sort((a, b) => a.agent_name.localeCompare(b.agent_name));
            const copy = prev.slice();
            copy[idx] = updated;
            return copy;
          });
        }
      )
      .subscribe();
    return () => {
      sb.removeChannel(channel);
    };
  }, []);

  // Separate MetaSecurity for display
  const meta = rows.find((r) => r.agent_name === "MetaSecurity");
  const others = rows.filter((r) => r.agent_name !== "MetaSecurity");

  return (
    <div className="space-y-4">
      {meta && (
        <div className="border border-agent-meta/60 bg-agent-meta/5 rounded-lg p-4 glow-red">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-agent-meta animate-pulse-slow" />
              <h3 className="font-mono font-bold text-agent-meta">MetaSecurity</h3>
              <span className="text-xs text-ink-faint">meta-oversight agent</span>
            </div>
            <HealthDot status={meta.health_status} />
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-sm">
            <Metric label="tasks" value={meta.tasks_completed} />
            <Metric label="accuracy" value={meta.accuracy_score.toFixed(2)} />
            <Metric label="challenges" value={meta.times_challenged} />
            <Metric label="overruled" value={meta.times_overruled} />
            <Metric label="jailbreaks caught" value={meta.jailbreak_attempts} highlight />
          </div>
        </div>
      )}

      <div className="bg-bg-panel border border-line rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-bg-elev border-b border-line">
            <tr className="text-left text-[11px] font-mono uppercase text-ink-dim">
              <th className="px-4 py-2">Agent</th>
              <th className="px-4 py-2">Tasks</th>
              <th className="px-4 py-2">Accuracy</th>
              <th className="px-4 py-2">Challenged</th>
              <th className="px-4 py-2">Overruled</th>
              <th className="px-4 py-2">Jailbreak Attempts</th>
              <th className="px-4 py-2">Health</th>
            </tr>
          </thead>
          <tbody>
            {others.map((r) => (
              <tr key={r.agent_name} className="border-b border-line/50 last:border-b-0">
                <td className="px-4 py-2">
                  <span
                    className="font-mono font-bold"
                    style={{ color: AGENT_COLORS[r.agent_name] || "#d6deeb" }}
                  >
                    {r.agent_name}
                  </span>
                </td>
                <td className="px-4 py-2 font-mono text-sm">{r.tasks_completed}</td>
                <td className="px-4 py-2 font-mono text-sm">
                  <AccuracyBar v={r.accuracy_score} />
                </td>
                <td className="px-4 py-2 font-mono text-sm">{r.times_challenged}</td>
                <td className="px-4 py-2 font-mono text-sm">{r.times_overruled}</td>
                <td className="px-4 py-2 font-mono text-sm">{r.jailbreak_attempts}</td>
                <td className="px-4 py-2">
                  <HealthDot status={r.health_status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Metric({ label, value, highlight }: { label: string; value: any; highlight?: boolean }) {
  return (
    <div>
      <div className="text-[10px] uppercase font-mono text-ink-faint">{label}</div>
      <div className={`font-mono text-xl ${highlight ? "text-agent-meta" : "text-ink"}`}>{value}</div>
    </div>
  );
}

function AccuracyBar({ v }: { v: number }) {
  const pct = Math.max(0, Math.min(1, v));
  const color = pct > 0.9 ? "#22c55e" : pct > 0.7 ? "#eab308" : "#ef4444";
  return (
    <div className="flex items-center gap-2">
      <div className="w-24 h-1.5 bg-bg-elev rounded">
        <div className="h-full rounded" style={{ width: `${pct * 100}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs" style={{ color }}>
        {pct.toFixed(2)}
      </span>
    </div>
  );
}

function HealthDot({ status }: { status: string }) {
  const color =
    status === "healthy"
      ? "#22c55e"
      : status === "investigating"
      ? "#eab308"
      : "#ef4444";
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs">
      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
      <span style={{ color }}>{status}</span>
    </span>
  );
}
