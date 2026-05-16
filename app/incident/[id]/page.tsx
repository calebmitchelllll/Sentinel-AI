'use client'

import { useState, useEffect } from 'react'
import { useRouter, useParams } from 'next/navigation'
import Link from 'next/link'
import { supabase } from '@/lib/supabase'
import AttackTimeline from '@/components/AttackTimeline'
import IncidentReport from '@/components/IncidentReport'

const severityColors: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  MEDIUM: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  LOW: 'bg-blue-500/15 text-blue-400 border border-blue-500/30',
}

interface MetaResult {
  agent: string
  injection_detected: boolean
  out_of_scope: boolean
  verdict: 'healthy' | 'compromised'
  hallucination_risk?: number
  warning?: string | null
  reason?: string
  detection_source?: 'pattern' | 'scope' | 'ai' | null
}

function MetaAuditPanel({ assessments }: { assessments: MetaResult[] }) {
  if (!assessments || assessments.length === 0) return null

  const [expanded, setExpanded] = useState<string | null>(null)

  const compromised = assessments.filter((a) => a.verdict === 'compromised')
  const injections = assessments.filter((a) => a.injection_detected)
  const allClear = compromised.length === 0 && injections.length === 0

  function riskColor(score: number) {
    if (score > 85) return 'text-red-400'
    if (score > 40) return 'text-yellow-400'
    return 'text-emerald-400'
  }

  return (
    <section>
      <h2 className="text-purple-400 font-mono text-xs uppercase tracking-widest mb-4">
        Meta Security Audit
      </h2>
      <div className="glass rounded-xl p-6">

        {/* Summary bar */}
        <div className="flex flex-wrap items-center gap-6 mb-6 pb-5 border-b border-white/[0.06]">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full animate-pulse ${allClear ? 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.5)]' : 'bg-red-400 shadow-[0_0_6px_rgba(248,113,113,0.5)]'}`} />
            <span className={`font-mono text-sm font-semibold ${allClear ? 'text-emerald-400' : 'text-red-400'}`}>
              {allClear ? 'All agents nominal' : `${compromised.length} agent${compromised.length > 1 ? 's' : ''} flagged`}
            </span>
          </div>
          <span className="text-white/25 text-xs font-mono">{assessments.length} agents monitored</span>
          <span className="text-white/25 text-xs font-mono">3-layer evaluation per agent</span>
          {injections.length > 0 && (
            <span className="text-xs font-mono text-red-400">{injections.length} injection attempt{injections.length > 1 ? 's' : ''} detected</span>
          )}
        </div>

        {/* Per-agent rows */}
        <div className="space-y-0">
          {assessments.map((a, i) => {
            const healthy = a.verdict === 'healthy'
            const isOpen = expanded === a.agent
            const risk = a.hallucination_risk ?? 0

            return (
              <div key={a.agent} className={i < assessments.length - 1 ? 'border-b border-white/[0.04]' : ''}>
                {/* Clickable header row */}
                <button
                  onClick={() => setExpanded(isOpen ? null : a.agent)}
                  className="w-full flex items-center justify-between py-3.5 text-left hover:bg-white/[0.03] transition-colors rounded-lg px-2 -mx-2"
                >
                  {/* Left: dot + name + chevron */}
                  <div className="flex items-center gap-3 w-40">
                    <div className={`w-2 h-2 rounded-full shrink-0 ${healthy ? 'bg-emerald-400 shadow-[0_0_5px_rgba(52,211,153,0.4)]' : 'bg-red-400 shadow-[0_0_5px_rgba(248,113,113,0.4)]'}`} />
                    <span className="text-white/80 font-mono text-sm">{a.agent}</span>
                    <span className="text-white/20 text-xs">{isOpen ? '▲' : '▼'}</span>
                  </div>

                  {/* Middle: verdict badge */}
                  <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded w-24 text-center ${
                    healthy
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : 'bg-red-500/15 text-red-400 border border-red-500/25'
                  }`}>
                    {a.verdict.toUpperCase()}
                  </span>

                  {/* Right: top-level flag summary */}
                  <div className="flex items-center gap-3 flex-wrap">
                    {a.detection_source === 'pattern' && (
                      <span className="text-xs font-mono text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded">PATTERN MATCH</span>
                    )}
                    {a.detection_source === 'scope' && (
                      <span className="text-xs font-mono text-orange-400 bg-orange-500/10 border border-orange-500/20 px-2 py-0.5 rounded">SCOPE VIOLATION</span>
                    )}
                    {a.detection_source === 'ai' && (
                      <span className="text-xs font-mono text-yellow-400 bg-yellow-500/10 border border-yellow-500/20 px-2 py-0.5 rounded">AI FLAGGED</span>
                    )}
                    {a.warning && healthy && (
                      <span className="text-xs font-mono text-yellow-400/70">elevated risk</span>
                    )}
                    {healthy && !a.warning && (
                      <span className="text-xs font-mono text-white/20">no flags</span>
                    )}
                  </div>
                </button>

                {/* Expanded: 3-layer evaluation breakdown */}
                {isOpen && (
                  <div className="ml-5 mb-3 mt-1 rounded-xl border border-white/[0.05] bg-white/[0.02] p-4 space-y-3">
                    <p className="text-white/20 text-xs font-mono uppercase tracking-widest mb-2">Evaluation layers</p>

                    {/* Layer 1: Injection pattern scan */}
                    <div className="flex items-start gap-3">
                      <span className={`text-xs font-mono mt-0.5 ${a.injection_detected ? 'text-red-400' : 'text-emerald-400'}`}>
                        {a.injection_detected ? '✗' : '✓'}
                      </span>
                      <div>
                        <p className="text-white/70 font-mono text-xs font-bold">Layer 1 — Injection Pattern Scan</p>
                        <p className="text-white/30 text-xs font-mono mt-0.5">
                          {a.injection_detected
                            ? 'FLAGGED — output matched a known prompt injection pattern (deterministic regex, high confidence)'
                            : 'Clean — no injection patterns detected in output (deterministic, not probabilistic)'}
                        </p>
                      </div>
                    </div>

                    {/* Layer 2: Scope boundary check */}
                    <div className="flex items-start gap-3">
                      <span className={`text-xs font-mono mt-0.5 ${a.out_of_scope ? 'text-orange-400' : 'text-emerald-400'}`}>
                        {a.out_of_scope ? '✗' : '✓'}
                      </span>
                      <div>
                        <p className="text-white/70 font-mono text-xs font-bold">Layer 2 — Role Boundary Check</p>
                        <p className="text-white/30 text-xs font-mono mt-0.5">
                          {a.out_of_scope
                            ? 'VIOLATION — agent output contained language outside its defined role (review manually)'
                            : `Clean — agent stayed within its defined role (${a.agent.toLowerCase()} scope enforced)`}
                        </p>
                      </div>
                    </div>

                    {/* Layer 3: AI hallucination scoring */}
                    <div className="flex items-start gap-3">
                      <span className={`text-xs font-mono mt-0.5 ${risk > 85 ? 'text-red-400' : risk > 40 ? 'text-yellow-400' : 'text-emerald-400'}`}>
                        {risk > 85 ? '✗' : '✓'}
                      </span>
                      <div className="flex-1">
                        <div className="flex items-center gap-3">
                          <p className="text-white/70 font-mono text-xs font-bold">Layer 3 — AI Hallucination Assessment</p>
                          <span className={`text-xs font-mono font-bold ${riskColor(risk)}`}>{risk}/100</span>
                        </div>
                        <div className="mt-1.5 h-1 w-full max-w-xs bg-white/[0.06] rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all ${risk > 85 ? 'bg-red-400' : risk > 40 ? 'bg-yellow-400' : 'bg-emerald-400'}`}
                            style={{ width: `${risk}%` }}
                          />
                        </div>
                        <p className="text-white/30 text-xs font-mono mt-1">
                          {risk > 85
                            ? 'High — NIM detected fabricated facts not present in the log evidence'
                            : risk > 40
                            ? 'Elevated — NIM found some uncertainty; treat output with caution'
                            : 'Low — NIM found no fabricated facts; output is grounded in log evidence'}
                        </p>
                      </div>
                    </div>

                    {/* NIM reasoning */}
                    {a.reason && (
                      <div className="pt-2 border-t border-white/[0.05]">
                        <p className="text-white/20 text-xs font-mono uppercase tracking-widest mb-1">MetaAgent reasoning</p>
                        <p className="text-white/40 text-xs font-mono italic">"{a.reason}"</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}

export default function IncidentPage() {
  const router = useRouter()
  const params = useParams()
  const id = params.id as string

  const [incident, setIncident] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    async function load() {
      const { data: { session } } = await supabase.auth.getSession()
      if (!session) { router.push('/auth/signin'); return }

      const res = await fetch(`/api/incidents/${id}`, {
        headers: { Authorization: `Bearer ${session.access_token}` },
      })

      if (!res.ok) {
        setError('Failed to load incident.')
        setLoading(false)
        return
      }

      const data = await res.json()
      setIncident(data)
      setLoading(false)
    }
    load()
  }, [id, router])

  function exportPDF() {
    if (!incident?.report) return
    import('jspdf').then(({ jsPDF }) => {
      const doc = new jsPDF()
      const report = incident.report
      const timeline: any[] = incident.attack_timeline || []
      let y = 20

      const addText = (text: string, size = 10, color = [255, 255, 255] as [number, number, number]) => {
        doc.setFontSize(size)
        doc.setTextColor(...color)
        const lines = doc.splitTextToSize(text, 180)
        if (y + lines.length * (size * 0.45) > 280) {
          doc.addPage()
          y = 20
        }
        doc.text(lines, 15, y)
        y += lines.length * (size * 0.45) + 4
      }

      doc.setFillColor(5, 5, 8)
      doc.rect(0, 0, 210, 297, 'F')

      addText('SentinelAI — Incident Report', 18, [192, 132, 252])
      addText(`Severity: ${report.severityScore || 'UNKNOWN'}`, 11, [200, 200, 200])
      addText(`Date: ${new Date(incident.created_at).toLocaleString()}`, 9, [136, 136, 136])
      y += 4

      addText('EXECUTIVE SUMMARY', 12, [192, 132, 252])
      addText(report.executiveSummary || 'N/A', 10, [220, 220, 220])
      y += 4

      addText('ROOT CAUSE', 12, [192, 132, 252])
      addText(report.rootCause || 'N/A', 10, [220, 220, 220])
      y += 4

      addText('BLAST RADIUS', 12, [192, 132, 252])
      addText(report.blastRadius || 'N/A', 10, [220, 220, 220])
      y += 4

      addText('ATTACK TIMELINE', 12, [192, 132, 252])
      timeline.forEach((step: any) => {
        addText(`${step.time}  ${step.event}`, 9, [220, 220, 220])
        addText(`  ${step.significance}`, 8, [136, 136, 136])
      })
      y += 4

      addText('IMMEDIATE ACTIONS', 12, [192, 132, 252])
      ;(report.immediateActions || []).forEach((a: string) => addText(`• ${a}`, 9, [220, 220, 220]))
      y += 4

      addText('LONG-TERM HARDENING', 12, [192, 132, 252])
      ;(report.longtermActions || []).forEach((a: string) => addText(`• ${a}`, 9, [220, 220, 220]))
      y += 4

      addText('AGENT DEBATE SUMMARY', 12, [192, 132, 252])
      addText(report.agentDebateSummary || 'N/A', 10, [220, 220, 220])

      doc.save(`incident-${id.slice(0, 8)}.pdf`)
    })
  }

  function exportMarkdown() {
    if (!incident?.report) return
    const report = incident.report
    const timeline: any[] = incident.attack_timeline || []
    const content = `# Security Incident Report

**Severity:** ${report.severityScore}
**Date:** ${new Date(incident.created_at).toLocaleString()}

## Executive Summary
${report.executiveSummary}

## Root Cause
${report.rootCause}

## Blast Radius
${report.blastRadius}

## Attack Timeline
${timeline.map((s: any) => `- **${s.time}** — ${s.event}: ${s.significance}`).join('\n')}

## Immediate Actions
${(report.immediateActions || []).map((a: string) => `- [ ] ${a}`).join('\n')}

## Long-Term Hardening
${(report.longtermActions || []).map((a: string) => `- [ ] ${a}`).join('\n')}

## Agent Debate Summary
${report.agentDebateSummary}
`
    const blob = new Blob([content], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `incident-${id.slice(0, 8)}.md`
    a.click()
    URL.revokeObjectURL(url)
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-purple-400 font-mono text-sm animate-pulse tracking-widest">Loading incident...</div>
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-red-400 font-mono text-sm">{error || 'Incident not found.'}</div>
      </div>
    )
  }

  const severity = incident.severity || incident.report?.severityScore || 'UNKNOWN'

  return (
    <div className="min-h-screen">
      <nav className="border-b border-white/[0.06] bg-black/30 backdrop-blur-xl px-6 py-4 sticky top-0 z-20">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-6">
            <Link href="/dashboard" className="text-xl font-thin tracking-[0.2em] uppercase">
              <span className="gradient-text">Sentinel</span>
              <span className="text-white/80">AI</span>
            </Link>
            <span className="text-white/20 text-sm hidden sm:block font-mono">/ Incident</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={exportPDF}
              className="px-3 py-1.5 border border-white/[0.08] bg-white/[0.03] rounded-lg text-white/50 text-xs hover:border-purple-500/30 hover:text-white/80 transition-all"
            >
              Export PDF
            </button>
            <button
              onClick={exportMarkdown}
              className="px-3 py-1.5 border border-white/[0.08] bg-white/[0.03] rounded-lg text-white/50 text-xs hover:border-purple-500/30 hover:text-white/80 transition-all"
            >
              Export Markdown
            </button>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-10 space-y-8">
        <div className="flex items-start gap-4 flex-wrap">
          <span className={`px-3 py-1 rounded-full text-sm font-bold font-mono ${severityColors[severity] || 'bg-white/10 text-white/40 border border-white/10'}`}>
            {severity}
          </span>
          <div>
            <h1 className="text-white/85 font-semibold text-xl tracking-wide">{incident.title}</h1>
            <p className="text-white/25 text-sm mt-1 font-mono">{new Date(incident.created_at).toLocaleString()}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <section>
            <h2 className="text-purple-400 font-mono text-xs uppercase tracking-widest mb-4">
              Attack Timeline
            </h2>
            <div className="glass rounded-xl p-6 h-full">
              <AttackTimeline timeline={incident.attack_timeline || []} />
            </div>
          </section>

          <section>
            <h2 className="text-purple-400 font-mono text-xs uppercase tracking-widest mb-4">
              Incident Summary
            </h2>
            <IncidentReport report={incident.report || {}} />
          </section>
        </div>

        {/* MetaAgent Security Audit */}
        <MetaAuditPanel assessments={incident.meta_assessments || []} />
      </main>
    </div>
  )
}
