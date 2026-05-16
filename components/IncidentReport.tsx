"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import SeverityBadge from "./SeverityBadge";
import AttackTimeline from "./AttackTimeline";
import type { IncidentReport as Report } from "@/lib/types";

// ---------------------------------------------------------------------------
// Field recovery helpers
// ---------------------------------------------------------------------------

/** Convert a parsed JSON report object into readable markdown for the Full Report section. */
function _jsonToMarkdown(j: Record<string, unknown>, incidentId: string): string {
  const bullets = (arr: unknown) =>
    Array.isArray(arr) ? (arr as string[]).map((x) => `- ${x}`).join("\n") : "";

  const timelineLines = (
    (j.attackTimeline ?? j.timeline ?? []) as Array<Record<string, unknown>>
  ).map((e) => {
    const label = [e.event, e.actor, e.impact].filter(Boolean).join(" — ");
    const ts = String(e.timestamp ?? e.at ?? "");
    return `- **${ts}** ${label}`;
  });

  return [
    `# Incident Report ${incidentId?.slice(0, 8) ?? ""}`,
    "",
    `## Executive Summary`,
    String(j.executiveSummary ?? ""),
    "",
    `## Severity`,
    String(j.severity ?? ""),
    "",
    `## Attack Timeline`,
    timelineLines.join("\n") || "(none recorded)",
    "",
    `## Root Cause`,
    String(j.rootCause ?? j.root_cause ?? ""),
    "",
    `## Blast Radius`,
    String(j.blastRadius ?? j.blast_radius ?? ""),
    "",
    `## Immediate Actions`,
    bullets(j.immediateActions ?? j.immediate_fixes),
    "",
    `## Long-term Actions`,
    bullets(j.longTermActions ?? j.longterm_fixes),
  ].join("\n");
}

/**
 * Find the first balanced JSON object in a string. Returns null if none found.
 * Handles JSON embedded in markdown code fences or preceded by prose.
 */
function _extractFirstJsonObject(text: string): Record<string, unknown> | null {
  const start = text.indexOf("{");
  if (start === -1) return null;
  let depth = 0;
  let inStr = false;
  let escape = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (escape) { escape = false; continue; }
    if (c === "\\" && inStr) { escape = true; continue; }
    if (c === '"') { inStr = !inStr; continue; }
    if (inStr) continue;
    if (c === "{") depth++;
    if (c === "}") {
      depth--;
      if (depth === 0) {
        try { return JSON.parse(text.slice(start, i + 1)); } catch { return null; }
      }
    }
  }
  return null;
}

/**
 * Resolve all display fields for the report, merging DB columns with any JSON
 * found in report_markdown. DB columns take priority when non-empty; JSON fills
 * in whatever is missing. This handles the common case where the orchestrator
 * saves raw reporter JSON into report_markdown but leaves the DB columns empty.
 */
function resolveFields(report: Report): {
  rootCause: string;
  blastRadius: string;
  timeline: Array<{ at: string; event: string }>;
  immediateFixes: string[];
  longtermFixes: string[];
  agentDebate: Array<{ agent: string; role: string; content: string }>;
  markdownContent: string;
} {
  // Always attempt to parse JSON from report_markdown so we can fill gaps.
  const j = report.report_markdown ? _extractFirstJsonObject(report.report_markdown) : null;

  // For each field: use the non-empty DB value if present, otherwise fall back to JSON.
  const rootCause =
    report.root_cause || String(j?.rootCause ?? j?.root_cause ?? "");
  const blastRadius =
    report.blast_radius || String(j?.blastRadius ?? j?.blast_radius ?? "");

  const timeline: Array<{ at: string; event: string }> = report.timeline?.length
    ? report.timeline
    : ((j?.attackTimeline ?? j?.timeline ?? []) as Array<Record<string, unknown>>).map(
        (e) => ({
          at: String(e.timestamp ?? e.at ?? ""),
          event: [e.event, e.actor, e.impact].filter(Boolean).join(" — "),
        })
      );

  const immediateFixes: string[] = report.immediate_fixes?.length
    ? report.immediate_fixes
    : ((j?.immediateActions ?? j?.immediate_fixes ?? []) as string[]);

  const longtermFixes: string[] = report.longterm_fixes?.length
    ? report.longterm_fixes
    : ((j?.longTermActions ?? j?.longterm_fixes ?? []) as string[]);

  const agentDebate: Array<{ agent: string; role: string; content: string }> =
    report.agent_debate?.length
      ? report.agent_debate.map((m) => ({ agent: m.agent, role: m.role, content: m.content }))
      : ((j?.agentDebateSummary ?? j?.agent_debate ?? []) as Array<Record<string, unknown>>).map(
          (d) => ({
            agent: String(d.agent ?? "Reporter"),
            role: String(d.role ?? d.topic ?? ""),
            content: String(d.content ?? d.resolution ?? ""),
          })
        );

  // Full Report section: if we pulled data from JSON, render it as markdown.
  // If the DB had the data, keep the original report_markdown (could be real markdown).
  const usedJson = j && (!report.root_cause || !report.blast_radius || !report.timeline?.length);
  const markdownContent = usedJson
    ? _jsonToMarkdown(j!, report.incident_id)
    : (report.report_markdown ?? "");

  return { rootCause, blastRadius, timeline, immediateFixes, longtermFixes, agentDebate, markdownContent };
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function IncidentReport({ report }: { report: Report }) {
  const f = resolveFields(report);

  const downloadMd = () => {
    const blob = new Blob([f.markdownContent], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelai-${report.incident_id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="bg-bg-panel border border-line rounded-lg p-5">
        <div className="flex items-start justify-between flex-wrap gap-3">
          <div>
            <div className="font-mono text-xs text-ink-faint">incident_report</div>
            <h1 className="text-2xl font-bold mt-1">Incident {report.incident_id.slice(0, 8)}</h1>
            <div className="mt-2 flex items-center gap-3">
              <SeverityBadge severity={report.severity} size="lg" />
              <span className="font-mono text-xs text-ink-dim">
                {new Date(report.created_at).toLocaleString()}
              </span>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={downloadMd}
              className="font-mono text-sm px-3 py-1.5 border border-line rounded hover:border-agent-detective hover:text-agent-detective"
            >
              ↓ markdown
            </button>
            <button
              onClick={() => window.print()}
              className="font-mono text-sm px-3 py-1.5 border border-line rounded hover:border-agent-reporter hover:text-agent-reporter"
            >
              ↓ pdf (print)
            </button>
          </div>
        </div>
      </div>

      <Card title="Attack Timeline" accent="#60a5fa">
        <AttackTimeline timeline={f.timeline} />
      </Card>

      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Root Cause" accent="#a78bfa">
          <p className="text-ink leading-relaxed whitespace-pre-wrap">
            {f.rootCause || "(not specified)"}
          </p>
        </Card>
        <Card title="Blast Radius" accent="#f87171">
          <p className="text-ink leading-relaxed whitespace-pre-wrap">
            {f.blastRadius || "(not specified)"}
          </p>
        </Card>
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Immediate Fixes" accent="#34d399">
          <Checklist items={f.immediateFixes} />
        </Card>
        <Card title="Long-term Fixes" accent="#22d3ee">
          <Checklist items={f.longtermFixes} />
        </Card>
      </div>

      <Card title="Agent Debate Summary" accent="#fb923c">
        <div className="space-y-3">
          {f.agentDebate.map((m, i) => (
            <div key={i} className="border border-line rounded p-3">
              <div className="flex items-center gap-2 mb-1 text-xs font-mono">
                <span className="font-bold">{m.agent}</span>
                <span className="text-ink-faint">{m.role}</span>
              </div>
              <p className="text-ink text-sm whitespace-pre-wrap">{m.content}</p>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Full Report" accent="#8b9bb4">
        <div className="prose-terminal">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{f.markdownContent}</ReactMarkdown>
        </div>
      </Card>
    </div>
  );
}

function Card({
  title,
  accent,
  children,
}: {
  title: string;
  accent: string;
  children: React.ReactNode;
}) {
  return (
    <section className="bg-bg-panel border border-line rounded-lg overflow-hidden">
      <header
        className="px-4 py-2 border-b border-line font-mono text-xs font-bold uppercase tracking-wider"
        style={{ color: accent }}
      >
        ▸ {title}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

function Checklist({ items }: { items: string[] }) {
  if (items.length === 0) {
    return <p className="text-ink-dim text-sm">(none specified)</p>;
  }
  return (
    <ul className="space-y-2">
      {items.map((it, i) => (
        <li key={i} className="flex items-start gap-2 text-sm">
          <input type="checkbox" className="mt-1 accent-agent-remediation" />
          <span className="text-ink">{it}</span>
        </li>
      ))}
    </ul>
  );
}
