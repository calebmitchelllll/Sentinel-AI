'use client'

import { useState, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { supabase } from '@/lib/supabase'
import AgentBenchmark from '@/components/AgentBenchmark'

const METRICS = [
  { label: 'Tasks Completed', desc: 'Total number of investigation tasks this agent has processed.' },
  { label: 'Accuracy Score', desc: 'Percentage of findings confirmed by the Validator agent.' },
  { label: 'Times Challenged', desc: 'How often the Validator challenged this agent\'s conclusions.' },
  { label: 'Times Overruled', desc: 'How often this agent\'s verdict was reversed by the Meta Agent.' },
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
    <div className="min-h-screen bg-[#0a0a0a]">
      <nav className="border-b border-[#2a2a2a] bg-[#111111] px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-8">
            <Link href="/dashboard" className="text-xl font-bold font-mono">
              <span className="text-[#00ff88]">Sentinel</span>
              <span className="text-white">AI</span>
            </Link>
            <div className="hidden sm:flex gap-6">
              <Link href="/dashboard" className="text-[#888888] hover:text-white text-sm font-mono transition-colors">Dashboard</Link>
              <Link href="/docs" className="text-[#888888] hover:text-white text-sm font-mono transition-colors">Docs</Link>
              <Link href="/benchmarks" className="text-[#00ff88] text-sm font-mono">Benchmarks</Link>
            </div>
          </div>
          <span className="text-[#888888] text-xs font-mono">Auto-refreshes every 30s</span>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <h1 className="text-white font-bold text-2xl mb-8">Agent Benchmark Dashboard</h1>

        {loading ? (
          <div className="text-[#00ff88] font-mono animate-pulse">Loading benchmarks...</div>
        ) : (
          <div className="rounded-lg border border-[#2a2a2a] bg-[#111111] overflow-hidden">
            <AgentBenchmark benchmarks={benchmarks} />
          </div>
        )}

        {/* Metric explanations */}
        <div className="mt-8 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {METRICS.map((m) => (
            <div key={m.label} className="rounded-lg border border-[#2a2a2a] bg-[#111111] p-4">
              <p className="text-[#00ff88] font-mono text-xs font-bold uppercase mb-1">{m.label}</p>
              <p className="text-[#888888] text-sm">{m.desc}</p>
            </div>
          ))}
        </div>
      </main>
    </div>
  )
}
