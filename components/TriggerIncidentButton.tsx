"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function TriggerIncidentButton() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onClick() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/trigger", { method: "POST" });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || "trigger failed");
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
          {loading ? "spinning up agents…" : "▶  Trigger demo incident"}
        </span>
        <span className="block text-[10px] text-ink-dim font-mono mt-1 text-left normal-case">
          stolen access key → privilege escalation → S3 exfiltration
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
