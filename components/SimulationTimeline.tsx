"use client";

import { useEffect, useState } from "react";

interface SimMeta {
  source: string;
  simulatedAt: string;
  cloudtrailCapturedAt: string;
  agentsDetectedAt: string;
}

interface Step {
  label: string;
  sublabel: string;
  time: string | null;
  color: string;
  done: boolean;
}

function fmt(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function delta(a: string | null | undefined, b: string | null | undefined): string {
  if (!a || !b) return "";
  const ms = Math.abs(Date.parse(b) - Date.parse(a));
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.round(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
}

export default function SimulationTimeline({
  incidentId,
  incidentCreatedAt,
  reportCreatedAt,
}: {
  incidentId: string;
  incidentCreatedAt: string;
  reportCreatedAt?: string | null;
}) {
  const [meta, setMeta] = useState<SimMeta | null>(null);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(`sentinel_sim_${incidentId}`);
      if (raw) setMeta(JSON.parse(raw));
    } catch { /* ignore */ }
  }, [incidentId]);

  // Update agentsDetectedAt once we have the real incidentCreatedAt
  const agentsAt = meta?.agentsDetectedAt ?? incidentCreatedAt;
  const reportAt = reportCreatedAt ?? null;

  const steps: Step[] = [
    {
      label: "Simulation triggered",
      sublabel: meta?.source === "stratus" ? "Stratus Red Team detonation" : "Demo dataset injected",
      time: meta?.simulatedAt ?? null,
      color: "#a855f7",
      done: !!meta,
    },
    {
      label: "CloudTrail captured",
      sublabel: `~30s propagation delay`,
      time: meta?.cloudtrailCapturedAt ?? null,
      color: "#3b82f6",
      done: !!meta,
    },
    {
      label: "Agents detected",
      sublabel: "6-agent pipeline started",
      time: agentsAt,
      color: "#22c55e",
      done: true,
    },
    {
      label: "Report generated",
      sublabel: "Investigation complete",
      time: reportAt,
      color: "#f59e0b",
      done: !!reportAt,
    },
  ];

  if (!meta && !reportCreatedAt) return null;

  return (
    <div className="bg-bg-panel border border-line rounded-lg p-5 space-y-4">
      <div className="flex items-center gap-2">
        <span
          className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border"
          style={{ color: "#a855f7", borderColor: "#a855f755", backgroundColor: "#a855f715" }}
        >
          SIMULATED ATTACK
        </span>
        <h3 className="font-mono text-sm text-ink-dim uppercase tracking-wider">
          Detection timeline
        </h3>
      </div>

      <div className="relative">
        {/* vertical connector line */}
        <div className="absolute left-[7px] top-3 bottom-3 w-px bg-line" />

        <ol className="space-y-5 relative">
          {steps.map((step, idx) => (
            <li key={idx} className="flex gap-4">
              {/* dot */}
              <div className="relative z-10 mt-0.5">
                <span
                  className="flex w-3.5 h-3.5 rounded-full border-2"
                  style={
                    step.done
                      ? { backgroundColor: step.color, borderColor: step.color }
                      : { backgroundColor: "transparent", borderColor: "#1a2744" }
                  }
                />
              </div>

              {/* content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline gap-3 flex-wrap">
                  <span
                    className="font-mono text-sm font-bold"
                    style={{ color: step.done ? step.color : "#8b9bb4" }}
                  >
                    {step.label}
                  </span>
                  {step.time && (
                    <span className="text-[11px] font-mono text-ink-faint">
                      {fmt(step.time)}
                    </span>
                  )}
                  {idx > 0 && step.time && steps[idx - 1].time && (
                    <span className="text-[10px] font-mono text-ink-faint">
                      (+{delta(steps[idx - 1].time, step.time)})
                    </span>
                  )}
                </div>
                <div className="text-[11px] font-mono text-ink-dim mt-0.5">
                  {step.sublabel}
                </div>
              </div>
            </li>
          ))}
        </ol>
      </div>

      {meta && reportAt && (
        <div className="pt-2 border-t border-line font-mono text-[11px] text-ink-dim flex gap-4 flex-wrap">
          <span>
            total detection time:{" "}
            <span className="text-ink font-bold">{delta(meta.simulatedAt, reportAt)}</span>
          </span>
          <span>
            cloudtrail lag:{" "}
            <span className="text-ink font-bold">
              {delta(meta.simulatedAt, meta.cloudtrailCapturedAt)}
            </span>
          </span>
          <span>
            agent pipeline:{" "}
            <span className="text-ink font-bold">{delta(agentsAt, reportAt)}</span>
          </span>
        </div>
      )}
    </div>
  );
}
