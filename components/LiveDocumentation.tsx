"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import SeverityBadge from "./SeverityBadge";
import type { LivingDoc } from "@/lib/types";

export default function LiveDocumentation({ docs }: { docs: LivingDoc[] }) {
  const [q, setQ] = useState("");
  const [tag, setTag] = useState<string | null>(null);
  const [sev, setSev] = useState<string | null>(null);

  const tags = useMemo(() => {
    const t = new Set<string>();
    docs.forEach((d) => d.tags?.forEach((x) => t.add(x)));
    return Array.from(t).sort();
  }, [docs]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return docs.filter((d) => {
      if (tag && !(d.tags || []).includes(tag)) return false;
      if (sev && d.severity !== sev) return false;
      if (!needle) return true;
      return (
        d.title.toLowerCase().includes(needle) ||
        d.content_markdown.toLowerCase().includes(needle) ||
        (d.attack_type || "").toLowerCase().includes(needle) ||
        (d.tags || []).some((t) => t.toLowerCase().includes(needle))
      );
    });
  }, [docs, q, tag, sev]);

  // Cross-incident patterns
  const patterns = useMemo(() => {
    const byTag: Record<string, number> = {};
    const byAttack: Record<string, number> = {};
    docs.forEach((d) => {
      (d.tags || []).forEach((t) => (byTag[t] = (byTag[t] || 0) + 1));
      if (d.attack_type) byAttack[d.attack_type] = (byAttack[d.attack_type] || 0) + 1;
    });
    return {
      topTags: Object.entries(byTag).sort((a, b) => b[1] - a[1]).slice(0, 4),
      topAttacks: Object.entries(byAttack).sort((a, b) => b[1] - a[1]).slice(0, 3),
    };
  }, [docs]);

  return (
    <div className="space-y-5">
      <div className="bg-bg-panel border border-line rounded-lg p-4">
        <div className="flex flex-wrap gap-3 items-center">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="search title / content / attack type…"
            className="flex-1 min-w-[240px] bg-bg-elev border border-line rounded px-3 py-2 font-mono text-sm focus:outline-none focus:border-agent-reporter"
          />
          <select
            value={sev || ""}
            onChange={(e) => setSev(e.target.value || null)}
            className="bg-bg-elev border border-line rounded px-2 py-2 font-mono text-sm"
          >
            <option value="">all severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <select
            value={tag || ""}
            onChange={(e) => setTag(e.target.value || null)}
            className="bg-bg-elev border border-line rounded px-2 py-2 font-mono text-sm"
          >
            <option value="">all tags</option>
            {tags.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>

        {(patterns.topTags.length > 0 || patterns.topAttacks.length > 0) && (
          <div className="mt-3 flex flex-wrap gap-4 text-xs font-mono text-ink-dim border-t border-line pt-3">
            {patterns.topTags.length > 0 && (
              <div>
                <span className="text-ink-faint">cross-incident tags:</span>{" "}
                {patterns.topTags.map(([t, n], i) => (
                  <span key={t}>
                    {i > 0 ? ", " : ""}
                    <span className="text-agent-reporter">{t}</span>×{n}
                  </span>
                ))}
              </div>
            )}
            {patterns.topAttacks.length > 0 && (
              <div>
                <span className="text-ink-faint">attack types:</span>{" "}
                {patterns.topAttacks.map(([t, n], i) => (
                  <span key={t}>
                    {i > 0 ? ", " : ""}
                    <span className="text-agent-detective">{t}</span>×{n}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {filtered.length === 0 ? (
        <div className="text-ink-dim text-sm font-mono">No matching docs.</div>
      ) : (
        <ul className="space-y-3">
          {filtered.map((d) => (
            <li key={d.id} className="bg-bg-panel border border-line rounded-lg p-4 hover:border-agent-reporter/60 transition">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    {d.severity && <SeverityBadge severity={d.severity} size="sm" />}
                    {d.attack_type && (
                      <span className="text-[10px] font-mono text-agent-detective border border-agent-detective/30 rounded px-1.5 py-0.5">
                        {d.attack_type}
                      </span>
                    )}
                    <span className="text-xs font-mono text-ink-faint">
                      {new Date(d.created_at).toLocaleString()}
                    </span>
                  </div>
                  <h3 className="font-bold text-ink">{d.title}</h3>
                  <p className="text-sm text-ink-dim mt-1 line-clamp-2">
                    {d.content_markdown.split("\n").slice(0, 3).join(" ").slice(0, 220)}…
                  </p>
                  {d.tags?.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {d.tags.map((t) => (
                        <span
                          key={t}
                          className="text-[10px] font-mono text-ink-dim border border-line rounded px-1.5 py-0.5"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                {d.incident_id && (
                  <Link
                    href={`/incident/${d.incident_id}`}
                    className="text-xs font-mono px-2 py-1 border border-line rounded text-agent-reporter hover:border-agent-reporter"
                  >
                    open →
                  </Link>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
