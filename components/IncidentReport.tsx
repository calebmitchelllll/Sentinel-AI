"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import SeverityBadge from "./SeverityBadge";
import AttackTimeline from "./AttackTimeline";
import type { IncidentReport as Report } from "@/lib/types";

export default function IncidentReport({ report }: { report: Report }) {
  const downloadMd = () => {
    const blob = new Blob([report.report_markdown], { type: "text/markdown" });
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
        <AttackTimeline timeline={report.timeline} />
      </Card>

      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Root Cause" accent="#a78bfa">
          <p className="text-ink leading-relaxed whitespace-pre-wrap">
            {report.root_cause || "(not specified)"}
          </p>
        </Card>
        <Card title="Blast Radius" accent="#f87171">
          <p className="text-ink leading-relaxed whitespace-pre-wrap">
            {report.blast_radius || "(not specified)"}
          </p>
        </Card>
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Immediate Fixes" accent="#34d399">
          <Checklist items={report.immediate_fixes || []} />
        </Card>
        <Card title="Long-term Fixes" accent="#22d3ee">
          <Checklist items={report.longterm_fixes || []} />
        </Card>
      </div>

      <Card title="Agent Debate Summary" accent="#fb923c">
        <div className="space-y-3">
          {(report.agent_debate || []).map((m, i) => (
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

      <Card title="Full Report (markdown)" accent="#8b9bb4">
        <div className="prose-terminal">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{report.report_markdown}</ReactMarkdown>
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
