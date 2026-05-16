'use client'

import { useState, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { supabase } from '@/lib/supabase'

interface Incident {
  id: string
  created_at: string
  title: string
  severity: string
  status: string
}

const AGENTS = ['Detective', 'Forensics', 'Remediation', 'Validator', 'Reporter', 'MetaAgent']

const severityColors: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border border-red-500',
  HIGH: 'bg-orange-500/20 text-orange-400 border border-orange-500',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500',
  LOW: 'bg-green-500/20 text-green-400 border border-green-500',
}

export default function DashboardPage() {
  const router = useRouter()
  const [user, setUser] = useState<any>(null)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [triggering, setTriggering] = useState(false)
  const [agentStates, setAgentStates] = useState<Record<string, string>>({})
  const [error, setError] = useState('')

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (!session) {
        router.push('/auth/signin')
        return
      }
      setUser(session.user)
      fetchIncidents(session.access_token)
    })
  }, [router])

  const fetchIncidents = useCallback(async (token: string) => {
    const res = await fetch('/api/incidents', {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (res.ok) {
      const data = await res.json()
      setIncidents(data)
    }
  }, [])

  async function handleSignOut() {
    await supabase.auth.signOut()
    router.push('/auth/signin')
  }

  async function handleTrigger() {
    setError('')
    setTriggering(true)

    const initialStates: Record<string, string> = {}
    AGENTS.forEach((a) => (initialStates[a] = 'idle'))
    setAgentStates(initialStates)

    // Animate agents sequentially
    const animateAgents = () => {
      let agentIdx = 0
      const interval = setInterval(() => {
        if (agentIdx < AGENTS.length) {
          const agent = AGENTS[agentIdx]
          setAgentStates((prev) => ({ ...prev, [agent]: 'investigating' }))
          agentIdx++
        } else {
          clearInterval(interval)
        }
      }, 4000)
      return interval
    }

    const animInterval = animateAgents()

    try {
      const { data: { session } } = await supabase.auth.getSession()
      if (!session) { router.push('/auth/signin'); return }

      const res = await fetch('/api/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: session.user.id }),
      })

      clearInterval(animInterval)

      if (!res.ok) {
        const errData = await res.json()
        throw new Error(errData.error || 'Trigger failed')
      }

      const data = await res.json()

      AGENTS.forEach((a) => setAgentStates((prev) => ({ ...prev, [a]: 'healthy' })))

      await fetchIncidents(session.access_token)

      setTimeout(() => {
        router.push(`/incident/${data.incidentId}`)
      }, 800)
    } catch (err: any) {
      clearInterval(animInterval)
      setError(err.message || 'Investigation failed')
      AGENTS.forEach((a) => setAgentStates((prev) => ({ ...prev, [a]: 'idle' })))
      setTriggering(false)
    }
  }

  function getDotStyle(state: string) {
    if (state === 'investigating') return 'bg-yellow-400 animate-pulse'
    if (state === 'healthy') return 'bg-[#00ff88]'
    if (state === 'compromised') return 'bg-red-400'
    return 'bg-[#2a2a2a]'
  }

  return (
    <div className="min-h-screen bg-[#0a0a0a]">
      {/* Nav */}
      <nav className="border-b border-[#2a2a2a] bg-[#111111] px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-8">
            <span className="text-xl font-bold font-mono">
              <span className="text-[#00ff88]">Sentinel</span>
              <span className="text-white">AI</span>
            </span>
            <div className="hidden sm:flex gap-6">
              <Link href="/dashboard" className="text-[#00ff88] text-sm font-mono">Dashboard</Link>
              <Link href="/docs" className="text-[#888888] hover:text-white text-sm font-mono transition-colors">Docs</Link>
              <Link href="/benchmarks" className="text-[#888888] hover:text-white text-sm font-mono transition-colors">Benchmarks</Link>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-[#888888] text-xs hidden sm:block">{user?.email}</span>
            <button
              onClick={handleSignOut}
              className="px-3 py-1.5 border border-[#2a2a2a] rounded-lg text-[#888888] text-xs hover:border-[#444444] hover:text-white transition-colors"
            >
              Sign Out
            </button>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-10">
        {/* Hero */}
        <div className="text-center mb-12">
          <h1 className="text-3xl sm:text-4xl font-bold mb-4">
            AWS Incident Response<br />
            <span className="text-[#00ff88]">Powered by Autonomous AI Agents</span>
          </h1>
          <p className="text-[#888888] text-sm max-w-xl mx-auto mb-8">
            Six specialized AI agents investigate your CloudTrail logs in parallel, identify threats,
            and generate actionable remediation reports — in under 2 minutes.
          </p>

          {!triggering ? (
            <button
              onClick={handleTrigger}
              className="px-8 py-4 bg-[#00ff88] text-black font-bold text-lg rounded-lg hover:bg-[#00cc66] transition-colors shadow-lg shadow-[#00ff88]/20"
            >
              🚨 Trigger Demo Incident
            </button>
          ) : (
            <div className="inline-flex flex-col items-center gap-4">
              <div className="text-[#00ff88] font-mono text-sm animate-pulse">
                Investigation in progress...
              </div>

              {/* Agent status indicators */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {AGENTS.map((agent) => (
                  <div
                    key={agent}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg border border-[#2a2a2a] bg-[#111111]"
                  >
                    <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${getDotStyle(agentStates[agent] || 'idle')}`} />
                    <span className="text-white text-xs font-mono">{agent}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {error && (
            <div className="mt-4 px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm inline-block">
              {error}
            </div>
          )}
        </div>

        {/* Incident Feed */}
        <div>
          <h2 className="text-white font-bold text-lg mb-4 font-mono">
            Recent Incidents
            <span className="ml-3 text-[#888888] text-sm font-normal">({incidents.length})</span>
          </h2>

          {incidents.length === 0 ? (
            <div className="rounded-lg border border-[#2a2a2a] bg-[#111111] p-8 text-center text-[#888888]">
              No incidents yet. Click &quot;Trigger Demo Incident&quot; to start your first investigation.
            </div>
          ) : (
            <div className="space-y-3">
              {incidents.map((incident) => (
                <Link
                  key={incident.id}
                  href={`/incident/${incident.id}`}
                  className="block rounded-lg border border-[#2a2a2a] bg-[#111111] p-4 hover:border-[#444444] transition-colors"
                >
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-3">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold font-mono ${severityColors[incident.severity] || 'bg-gray-500/20 text-gray-400 border border-gray-500'}`}>
                        {incident.severity}
                      </span>
                      <span className="text-white font-medium">{incident.title}</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className={`text-xs font-mono px-2 py-0.5 rounded ${incident.status === 'resolved' ? 'text-green-400' : 'text-yellow-400'}`}>
                        {incident.status}
                      </span>
                      <span className="text-[#888888] text-xs">
                        {new Date(incident.created_at).toLocaleString()}
                      </span>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
