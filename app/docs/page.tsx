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
              <Link href="/docs" className="text-[#00ff88] text-sm font-mono">Docs</Link>
              <Link href="/benchmarks" className="text-[#888888] hover:text-white text-sm font-mono transition-colors">Benchmarks</Link>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <h1 className="text-white font-bold text-2xl mb-6">
          Living Documentation
          <span className="ml-3 text-[#888888] text-base font-normal">({docs.length} documents)</span>
        </h1>

        {loading ? (
          <div className="text-[#00ff88] font-mono animate-pulse">Loading documents...</div>
        ) : docs.length === 0 ? (
          <div className="rounded-lg border border-[#2a2a2a] bg-[#111111] p-8 text-center text-[#888888]">
            No documents yet. Trigger an incident to generate living documentation.
          </div>
        ) : (
          <LiveDocumentation docs={docs} />
        )}
      </main>
    </div>
  )
}
