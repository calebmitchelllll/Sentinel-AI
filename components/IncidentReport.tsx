'use client'

interface Report {
  executiveSummary?: string
  severityScore?: string
  rootCause?: string
  blastRadius?: string
  immediateActions?: string[]
  longtermActions?: string[]
  agentDebateSummary?: string
}

const severityColors: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border border-red-500',
  HIGH: 'bg-orange-500/20 text-orange-400 border border-orange-500',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500',
  LOW: 'bg-green-500/20 text-green-400 border border-green-500',
}

function SectionCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-[#2a2a2a] bg-[#111111] p-4">
      <h3 className="text-[#00ff88] font-mono text-xs font-bold uppercase tracking-widest mb-3">
        {title}
      </h3>
      {children}
    </div>
  )
}

export default function IncidentReport({ report }: { report: Report }) {
  const severity = report.severityScore || 'UNKNOWN'
  const severityClass = severityColors[severity] || 'bg-gray-500/20 text-gray-400 border border-gray-500'

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <span className={`px-3 py-1 rounded-full text-sm font-bold font-mono ${severityClass}`}>
          {severity}
        </span>
      </div>

      <SectionCard title="Executive Summary">
        <p className="text-white text-sm leading-relaxed">{report.executiveSummary || 'N/A'}</p>
      </SectionCard>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <SectionCard title="Root Cause">
          <p className="text-white text-sm leading-relaxed">{report.rootCause || 'N/A'}</p>
        </SectionCard>
        <SectionCard title="Blast Radius">
          <p className="text-white text-sm leading-relaxed">{report.blastRadius || 'N/A'}</p>
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <SectionCard title="Immediate Actions">
          <ul className="space-y-3">
            {(report.immediateActions || []).map((action, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="text-[#00ff88] mt-0.5 shrink-0">☐</span>
                <span className="text-white text-sm break-words min-w-0">{action}</span>
              </li>
            ))}
            {(!report.immediateActions || report.immediateActions.length === 0) && (
              <li className="text-[#888888] text-sm">No immediate actions defined.</li>
            )}
          </ul>
        </SectionCard>

        <SectionCard title="Long-Term Hardening">
          <ul className="space-y-3">
            {(report.longtermActions || []).map((action, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="text-blue-400 mt-0.5 shrink-0">☐</span>
                <span className="text-white text-sm break-words min-w-0">{action}</span>
              </li>
            ))}
            {(!report.longtermActions || report.longtermActions.length === 0) && (
              <li className="text-[#888888] text-sm">No long-term actions defined.</li>
            )}
          </ul>
        </SectionCard>
      </div>

      <SectionCard title="Agent Debate Summary">
        <p className="text-white text-sm leading-relaxed">{report.agentDebateSummary || 'N/A'}</p>
      </SectionCard>
    </div>
  )
}
