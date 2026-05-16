'use client'

import { useState, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { supabase } from '@/lib/supabase'
import AgentBenchmark from '@/components/AgentBenchmark'

const METRICS = [
  { label: 'Tasks Completed', desc: 'Total number of investigation tasks this agent has processed.' },
  { label: 'Accuracy Score', desc: 'Percentage of findings confirmed by the Validator agent.' },
  { label: 'Times Challenged', desc: "How often the Validator challenged this agent's conclusions." },
  { label: 'Times Overruled', desc: "How often this agent's verdict was reversed by the Meta Agent." },
  { label: 'Jailbreak Attempts Detected', desc: 'Count of prompt injection patterns detected in outputs.' },
  { label: 'Health Status', desc: 'Current operating state: healthy (normal), investigating (in progress), compromised (flagged by Meta Agent).' },
]

export default function BenchmarksPage() {
  const router = useRouter()
  const [benchmarks, setBenchmarks] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [token, setToken] = useState('')

  const fetchBenchmarks = useCallback(async (accessToken: string) => {
    const res = await fetch('/api/benchmarks', {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    if (res.ok) {
      const data = await res.json()
      setBenchmarks(data)
    }
    setLoading(false)
  }, [])

  useEffect(() => {
    async function init() {
      const { data: { session } } = await supabase.auth.getSession()
      if (!session) { router.push('/auth/signin'); return }
      setToken(session.access_token)
      fetchBenchmarks(session.access_token)
    }
    init()
  }, [router, fetchBenchmarks])

  useEffect(() => {
    if (!token) return
    const interval = setInterval(() => fetchBenchmarks(token), 30000)
    return () => clearInterval(interval)
  }, [token, fetchBenchmarks])

  return (
    <div className="min-h-screen">
      <nav className="border-b border-white/[0.06] bg-black/30 backdrop-blur-xl px-6 py-4 sticky top-0 z-20">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-8">
            <Link href="/dashboard" className="text-xl font-thin tracking-[0.2em] uppercase">
              <span className="gradient-text">Sentinel</span>
              <span className="text-white/80">AI</span>
            </Link>
            <div className="hidden sm:flex gap-6">
              <Link href="/dashboard" className="text-white/30 hover:text-white/70 text-sm font-mono tracking-wide transition-colors">Dashboard</Link>
              <Link href="/docs" className="text-white/30 hover:text-white/70 text-sm font-mono tracking-wide transition-colors">Docs</Link>
              <Link href="/benchmarks" className="text-purple-400 text-sm font-mono tracking-wide">Benchmarks</Link>
            </div>
          </div>
          <span className="text-white/20 text-xs font-mono">Auto-refreshes every 30s</span>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-10">
        <div className="mb-10">
          <p className="text-white/25 font-mono text-xs tracking-[0.35em] uppercase mb-3">Performance Monitoring</p>
          <h1 className="text-4xl font-thin tracking-[0.08em] uppercase gradient-text">Agent Benchmarks</h1>
        </div>

        {loading ? (
          <div className="text-purple-400 font-mono text-sm animate-pulse tracking-widest">Loading benchmarks...</div>
        ) : (
          <div className="glass rounded-xl overflow-hidden">
            <AgentBenchmark benchmarks={benchmarks} />
          </div>
        )}

        <div className="mt-8 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {METRICS.map((m) => (
            <div key={m.label} className="glass rounded-xl p-4">
              <p className="text-purple-400 font-mono text-xs font-bold uppercase tracking-widest mb-2">{m.label}</p>
              <p className="text-white/35 text-sm leading-relaxed">{m.desc}</p>
            </div>
          ))}
        </div>
      </main>
    </div>
  )
}
