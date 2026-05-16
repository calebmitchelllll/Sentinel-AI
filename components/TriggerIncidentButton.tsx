"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";

export default function TriggerIncidentButton() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (loading) {
      setElapsed(0);
      timerRef.current = setInterval(() => setElapsed((s) => s + 1), 1000);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [loading]);

  async function onClick() {
    setLoading(true);
    setError(null);
    const simulatedAt = new Date().toISOString();
    try {
      const res = await fetch("/api/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ persist: true }),
      });
      const json = await res.json();
      if (json.error) throw new Error(json.details ?? json.error);
      if (!json.incidentId) throw new Error("No incidentId returned — check server logs");

      // Record simulation metadata so dashboard + incident page can show provenance
      try {
        localStorage.setItem(
          `sentinel_sim_${json.incidentId}`,
          JSON.stringify({
            source: "demo",
            simulatedAt,
            // CloudTrail propagation typically takes ~30s
            cloudtrailCapturedAt: new Date(Date.parse(simulatedAt) + 30_000).toISOString(),
            agentsDetectedAt: new Date().toISOString(),
          })
        );
      } catch { /* localStorage unavailable — non-fatal */ }

      router.push(`/incident/${json.incidentId}`);
    } catch (e: any) {
      setLoading(false);
      setError(e?.message || "unknown error");
    }
  }

  return (
    <div>
      <button
        onClick={onClick}
        disabled={loading}
        className="font-mono group relative px-5 py-3 bg-sev-crit/10 border border-sev-crit/60 text-sev-crit hover:bg-sev-crit/20 rounded-lg transition glow-red disabled:opacity-50"
      >
        <span className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full bg-sev-crit ${loading ? "animate-pulse-slow" : ""}`} />
          {loading
            ? `agents running… ${elapsed}s`
            : "▶  Trigger demo incident"}
        </span>
        <span className="block text-[10px] text-ink-dim font-mono mt-1 text-left normal-case">
          {loading
            ? elapsed < 30 ? "detective analyzing logs…"
              : elapsed < 60 ? "forensics deep dive…"
              : elapsed < 90 ? "validator challenging findings…"
              : elapsed < 150 ? "agents debating + remediation…"
              : elapsed < 210 ? "reporter synthesizing…"
              : "finalizing report…"
            : "stolen access key → privilege escalation → S3 exfiltration"}
        </span>
      </button>
      {error && (
        <div className="mt-2 text-xs font-mono text-sev-crit border border-sev-crit/30 bg-sev-crit/10 rounded p-2">
          {error}
        </div>
      )}
    </div>
  );
}
