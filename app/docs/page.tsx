'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { supabase } from '@/lib/supabase'
import LiveDocumentation from '@/components/LiveDocumentation'

export default function DocsPage() {
  const router = useRouter()
  const [docs, setDocs] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function load() {
      const { data: { session } } = await supabase.auth.getSession()
      if (!session) { router.push('/auth/signin'); return }

      const res = await fetch('/api/docs', {
        headers: { Authorization: `Bearer ${session.access_token}` },
      })

      if (res.ok) {
        const data = await res.json()
        setDocs(data)
      }
      setLoading(false)
    }
    load()
  }, [router])

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
              <Link href="/docs" className="text-purple-400 text-sm font-mono tracking-wide">Docs</Link>
              <Link href="/benchmarks" className="text-white/30 hover:text-white/70 text-sm font-mono tracking-wide transition-colors">Benchmarks</Link>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-10">
        <div className="mb-8">
          <p className="text-white/25 font-mono text-xs tracking-[0.35em] uppercase mb-3">Auto-generated Reports</p>
          <h1 className="text-4xl font-thin tracking-[0.08em] uppercase">
            <span className="gradient-text">Living</span>
            <span className="text-white/80"> Documentation</span>
            <span className="ml-4 text-white/20 text-xl font-normal normal-case tracking-normal">({docs.length})</span>
          </h1>
        </div>

        {loading ? (
          <div className="text-purple-400 font-mono text-sm animate-pulse tracking-widest">Loading documents...</div>
        ) : docs.length === 0 ? (
          <div className="glass rounded-xl p-10 text-center text-white/25 text-sm">
            No documents yet. Trigger an incident to generate living documentation.
          </div>
        ) : (
          <LiveDocumentation docs={docs} />
        )}
      </main>
    </div>
  )
}
