"use client"
import { useEffect, useState } from "react"
import { createSupabaseBrowserClient } from "@/lib/supabase-client"
import IncidentReportView from "@/components/IncidentReport"

export default function IncidentPage({ params }: { params: { id: string } }) {
  const [incident, setIncident] = useState<any>(null)
  const [report, setReport] = useState<any>(null)

  useEffect(() => {
    const supabase = createSupabaseBrowserClient()
    async function load() {
      const [{ data: inc }, { data: rep }] = await Promise.all([
        supabase.from("incidents").select("*").eq("id", params.id).single(),
        supabase.from("incident_reports").select("*").eq("incident_id", params.id).maybeSingle(),
      ])
      setIncident(inc)
      setReport(rep)
    }
    load()
  }, [params.id])

  return (
    <div className="min-h-screen bg-black text-white p-8 max-w-4xl mx-auto">

      <a href="/dashboard" className="text-gray-500 text-sm font-mono hover:text-white">
        ← back to dashboard
      </a>

      {/* Simulated attack banner */}
      <div className="mt-6 mb-6 px-4 py-2 rounded-lg text-xs font-mono font-bold tracking-widest uppercase flex items-center gap-2"
        style={{ background: "#a855f715", border: "1px solid #a855f740", color: "#c084fc" }}>
        ⚠ Simulated Attack — Synthetic data only · No real systems affected
      </div>

      {incident && (
        <div className="mb-8 border-b border-gray-800 pb-6">
          <h1 className="text-3xl font-bold font-mono">
            Incident {incident.id.slice(0, 8)}
          </h1>
          <div className="flex gap-3 mt-3 flex-wrap">
            <span className="text-red-400 border border-red-400 px-3 py-1 text-xs font-mono rounded">
              ● {incident.severity}
            </span>
            <span className="text-yellow-400 border border-yellow-400 px-3 py-1 text-xs font-mono rounded">
              {incident.status?.toUpperCase()}
            </span>
            <span className="text-gray-400 text-sm font-mono">
              {new Date(incident.created_at).toLocaleString()}
            </span>
          </div>
          {incident.summary && (
            <p className="text-gray-300 mt-4 text-sm leading-relaxed">
              {incident.summary}
            </p>
          )}
        </div>
      )}

      {report
        ? <IncidentReportView report={report} />
        : <p className="text-gray-600 font-mono text-sm">Report not yet available.</p>
      }

    </div>
  )
}
