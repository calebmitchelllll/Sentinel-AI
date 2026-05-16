'use client'

import { useState, useEffect } from 'react'
import { useRouter, useParams } from 'next/navigation'
import Link from 'next/link'
import { supabase } from '@/lib/supabase'
import AttackTimeline from '@/components/AttackTimeline'
import IncidentReport from '@/components/IncidentReport'

const severityColors: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border border-red-500',
  HIGH: 'bg-orange-500/20 text-orange-400 border border-orange-500',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500',
  LOW: 'bg-green-500/20 text-green-400 border border-green-500',
}

interface MetaResult {
  agent: string
  hallucination_risk: number
  injection_detected: boolean
  out_of_scope: boolean
  verdict: 'healthy' | 'compromised'
}

function MetaAuditPanel({ assessments }: { assessments: MetaResult[] }) {
  if (!assessments || assessments.length === 0) return null

  const compromised = assessments.filter((a) => a.verdict === 'compromised')
  const injections = assessments.filter((a) => a.injection_detected)
  const allClear = compromised.length === 0 && injections.length === 0
  const avgRisk = Math.round(assessments.reduce((s, a) => s + (a.hallucination_risk ?? 0), 0) / assessments.length)

  return (
    <section>
      <h2 className="text-[#00ff88] font-mono text-sm uppercase tracking-widest mb-4">
        Meta Security Audit
      </h2>
      <div className="rounded-lg border border-[#2a2a2a] bg-[#111111] p-6">

        {/* Summary bar */}
        <div className="flex flex-wrap items-center gap-6 mb-6 pb-5 border-b border-[#2a2a2a]">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${allClear ? 'bg-[#00ff88] animate-pulse' : 'bg-red-400 animate-pulse'}`} />
            <span className={`font-mono text-sm font-bold ${allClear ? 'text-[#00ff88]' : 'text-red-400'}`}>
              {allClear ? 'All agents nominal' : `${compromised.length} agent${compromised.length > 1 ? 's' : ''} flagged`}
            </span>
          </div>
          <span className="text-[#555] text-xs font-mono">{assessments.length} agents monitored</span>
          <span className="text-[#555] text-xs font-mono">3 integrity checks</span>
          <span className="text-[#555] text-xs font-mono">avg hallucination risk: {avgRisk}%</span>
        </div>

        {/* Per-agent rows */}
        <div className="space-y-0">
          {assessments.map((a, i) => {
            const healthy = a.verdict === 'healthy'
            const risk = a.hallucination_risk ?? 0
            const riskColor = risk < 30 ? 'bg-[#00ff88]' : risk < 60 ? 'bg-yellow-400' : 'bg-red-400'

            return (
              <div
                key={a.agent}
                className={`flex items-center justify-between py-3 ${i < assessments.length - 1 ? 'border-b border-[#1a1a1a]' : ''}`}
              >
                {/* Left: dot + name */}
                <div className="flex items-center gap-3 w-36">
                  <div className={`w-2 h-2 rounded-full shrink-0 ${healthy ? 'bg-[#00ff88]' : 'bg-red-400'}`} />
                  <span className="text-white font-mono text-sm">{a.agent}</span>
                </div>

                {/* Middle: verdict badge */}
                <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded w-24 text-center ${
                  healthy
                    ? 'bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/20'
                    : 'bg-red-500/20 text-red-400 border border-red-500/30'
                }`}>
                  {a.verdict.toUpperCase()}
                </span>

                {/* Right: risk bar + flags */}
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2">
                    <span className="text-[#555] text-xs font-mono w-16 text-right">risk {risk}%</span>
                    <div className="w-24 h-1.5 bg-[#2a2a2a] rounded-full overflow-hidden">
                      <div className={`h-full rounded-full transition-all ${riskColor}`} style={{ width: `${risk}%` }} />
                    </div>
                  </div>
                  {a.injection_detected && (
                    <span className="text-xs font-mono text-red-400 bg-red-500/10 border border-red-500/30 px-2 py-0.5 rounded">
                      INJECTION DETECTED
                    </span>
                  )}
                  {a.out_of_scope && (
                    <span className="text-xs font-mono text-yellow-400 bg-yellow-500/10 border border-yellow-500/30 px-2 py-0.5 rounded">
                      OUT OF SCOPE
                    </span>
                  )}
                  {!a.injection_detected && !a.out_of_scope && (
                    <span className="text-xs font-mono text-[#555]">no flags</span>
                  )}
                </div>
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

      doc.setFillColor(10, 10, 10)
      doc.rect(0, 0, 210, 297, 'F')

      addText('SentinelAI — Incident Report', 18, [0, 255, 136])
      addText(`Severity: ${report.severityScore || 'UNKNOWN'}`, 11, [200, 200, 200])
      addText(`Date: ${new Date(incident.created_at).toLocaleString()}`, 9, [136, 136, 136])
      y += 4

      addText('EXECUTIVE SUMMARY', 12, [0, 255, 136])
      addText(report.executiveSummary || 'N/A', 10, [220, 220, 220])
      y += 4

      addText('ROOT CAUSE', 12, [0, 255, 136])
      addText(report.rootCause || 'N/A', 10, [220, 220, 220])
      y += 4

      addText('BLAST RADIUS', 12, [0, 255, 136])
      addText(report.blastRadius || 'N/A', 10, [220, 220, 220])
      y += 4

      addText('ATTACK TIMELINE', 12, [0, 255, 136])
      timeline.forEach((step: any) => {
        addText(`${step.time}  ${step.event}`, 9, [220, 220, 220])
        addText(`  ${step.significance}`, 8, [136, 136, 136])
      })
      y += 4

      addText('IMMEDIATE ACTIONS', 12, [0, 255, 136])
      ;(report.immediateActions || []).forEach((a: string) => addText(`• ${a}`, 9, [220, 220, 220]))
      y += 4

      addText('LONG-TERM HARDENING', 12, [0, 255, 136])
      ;(report.longtermActions || []).forEach((a: string) => addText(`• ${a}`, 9, [220, 220, 220]))
      y += 4

      addText('AGENT DEBATE SUMMARY', 12, [0, 255, 136])
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
      <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center">
        <div className="text-[#00ff88] font-mono animate-pulse">Loading incident...</div>
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center">
        <div className="text-red-400 font-mono">{error || 'Incident not found.'}</div>
      </div>
    )
  }

  const severity = incident.severity || incident.report?.severityScore || 'UNKNOWN'

  return (
    <div className="min-h-screen bg-[#0a0a0a]">
      <nav className="border-b border-[#2a2a2a] bg-[#111111] px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-6">
            <Link href="/dashboard" className="text-xl font-bold font-mono">
              <span className="text-[#00ff88]">Sentinel</span>
              <span className="text-white">AI</span>
            </Link>
            <span className="text-[#888888] text-sm hidden sm:block">/ Incident</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={exportPDF}
              className="px-3 py-1.5 bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg text-white text-xs hover:border-[#00ff88] transition-colors"
            >
              Export PDF
            </button>
            <button
              onClick={exportMarkdown}
              className="px-3 py-1.5 bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg text-white text-xs hover:border-[#00ff88] transition-colors"
            >
              Export Markdown
            </button>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        <div className="flex items-start gap-4 flex-wrap">
          <span className={`px-3 py-1 rounded-full text-sm font-bold font-mono ${severityColors[severity] || 'bg-gray-500/20 text-gray-400 border border-gray-500'}`}>
            {severity}
          </span>
          <div>
            <h1 className="text-white font-bold text-xl">{incident.title}</h1>
            <p className="text-[#888888] text-sm mt-1">{new Date(incident.created_at).toLocaleString()}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <section>
            <h2 className="text-[#00ff88] font-mono text-sm uppercase tracking-widest mb-4">
              Attack Timeline
            </h2>
            <div className="rounded-lg border border-[#2a2a2a] bg-[#111111] p-6 h-full">
              <AttackTimeline timeline={incident.attack_timeline || []} />
            </div>
          </section>

          <section>
            <h2 className="text-[#00ff88] font-mono text-sm uppercase tracking-widest mb-4">
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
