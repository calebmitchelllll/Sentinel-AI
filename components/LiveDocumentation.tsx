'use client'

import { useState } from 'react'
import ReactMarkdown from 'react-markdown'

interface LiveDoc {
  id: string
  created_at: string
  incident_id: string
  content: string
  tags: string[]
}

export default function LiveDocumentation({ docs }: { docs: LiveDoc[] }) {
  const [selected, setSelected] = useState<LiveDoc | null>(docs[0] || null)
  const [search, setSearch] = useState('')

  const filtered = docs.filter((doc) => {
    const q = search.toLowerCase()
    return (
      doc.id.toLowerCase().includes(q) ||
      (doc.tags || []).some((t) => t?.toLowerCase().includes(q)) ||
      doc.content.toLowerCase().includes(q)
    )
  })

  return (
    <div className="flex gap-4 h-[70vh]">
      {/* Left sidebar */}
      <div className="w-72 shrink-0 flex flex-col gap-2">
        <input
          type="text"
          placeholder="Search docs..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full px-3 py-2 bg-white/[0.04] border border-white/[0.08] rounded-xl text-white text-sm placeholder-white/20 focus:outline-none focus:border-purple-500/40 transition-all"
        />
        <div className="flex-1 overflow-y-auto space-y-1.5">
          {filtered.map((doc) => (
            <button
              key={doc.id}
              onClick={() => setSelected(doc)}
              className={`w-full text-left p-3 rounded-xl border transition-all ${
                selected?.id === doc.id
                  ? 'border-purple-500/30 bg-purple-500/[0.07]'
                  : 'border-white/[0.06] bg-white/[0.02] hover:bg-white/[0.04]'
              }`}
            >
              <p className="text-white/70 text-xs font-mono truncate">
                Incident {doc.incident_id?.slice(0, 8)}...
              </p>
              <p className="text-white/25 text-xs mt-1 font-mono">
                {new Date(doc.created_at).toLocaleString()}
              </p>
              <div className="flex gap-1 flex-wrap mt-1.5">
                {(doc.tags || []).filter(Boolean).map((tag, i) => (
                  <span key={i} className="px-1.5 py-0.5 rounded text-[10px] bg-white/[0.05] text-white/30 border border-white/[0.06]">
                    {tag}
                  </span>
                ))}
              </div>
            </button>
          ))}
          {filtered.length === 0 && (
            <p className="text-white/25 text-sm text-center py-4 font-mono">No documents found.</p>
          )}
        </div>
      </div>

      {/* Right panel */}
      <div className="flex-1 overflow-y-auto glass rounded-xl p-6">
        {selected ? (
          <div className="prose prose-invert prose-sm max-w-none">
            <ReactMarkdown
              components={{
                h1: ({ children }) => <h1 className="text-purple-400 text-2xl font-semibold mb-4 tracking-wide">{children}</h1>,
                h2: ({ children }) => <h2 className="text-purple-300 text-lg font-semibold mt-6 mb-2">{children}</h2>,
                h3: ({ children }) => <h3 className="text-white/80 text-base font-semibold mt-4 mb-2">{children}</h3>,
                p: ({ children }) => <p className="text-white/60 text-sm leading-relaxed mb-3">{children}</p>,
                li: ({ children }) => <li className="text-white/60 text-sm">{children}</li>,
                code: ({ children }) => (
                  <code className="bg-white/[0.06] text-purple-300 px-1.5 py-0.5 rounded font-mono text-xs border border-white/[0.06]">{children}</code>
                ),
                pre: ({ children }) => (
                  <pre className="bg-white/[0.04] border border-white/[0.06] rounded-xl p-4 overflow-x-auto mb-4">{children}</pre>
                ),
                strong: ({ children }) => <strong className="text-purple-300 font-semibold">{children}</strong>,
              }}
            >
              {selected.content}
            </ReactMarkdown>
          </div>
        ) : (
          <div className="flex items-center justify-center h-full text-white/25 font-mono text-sm">
            Select a document from the list to view it.
          </div>
        )}
      </div>
    </div>
  )
}
