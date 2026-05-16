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
          className="w-full px-3 py-2 bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg text-white text-sm placeholder-[#888888] focus:outline-none focus:border-[#00ff88]"
        />
        <div className="flex-1 overflow-y-auto space-y-2">
          {filtered.map((doc) => (
            <button
              key={doc.id}
              onClick={() => setSelected(doc)}
              className={`w-full text-left p-3 rounded-lg border transition-colors ${
                selected?.id === doc.id
                  ? 'border-[#00ff88] bg-[#00ff88]/10'
                  : 'border-[#2a2a2a] bg-[#111111] hover:border-[#444444]'
              }`}
            >
              <p className="text-white text-xs font-mono truncate">
                Incident {doc.incident_id?.slice(0, 8)}...
              </p>
              <p className="text-[#888888] text-xs mt-1">
                {new Date(doc.created_at).toLocaleString()}
              </p>
              <div className="flex gap-1 flex-wrap mt-1">
                {(doc.tags || []).filter(Boolean).map((tag, i) => (
                  <span key={i} className="px-1.5 py-0.5 rounded text-[10px] bg-[#2a2a2a] text-[#888888]">
                    {tag}
                  </span>
                ))}
              </div>
            </button>
          ))}
          {filtered.length === 0 && (
            <p className="text-[#888888] text-sm text-center py-4">No documents found.</p>
          )}
        </div>
      </div>

      {/* Right panel */}
      <div className="flex-1 overflow-y-auto rounded-lg border border-[#2a2a2a] bg-[#111111] p-6">
        {selected ? (
          <div className="prose prose-invert prose-sm max-w-none">
            <ReactMarkdown
              components={{
                h1: ({ children }) => <h1 className="text-[#00ff88] text-2xl font-bold mb-4">{children}</h1>,
                h2: ({ children }) => <h2 className="text-[#00ff88] text-lg font-bold mt-6 mb-2">{children}</h2>,
                h3: ({ children }) => <h3 className="text-white text-base font-bold mt-4 mb-2">{children}</h3>,
                p: ({ children }) => <p className="text-white text-sm leading-relaxed mb-3">{children}</p>,
                li: ({ children }) => <li className="text-white text-sm">{children}</li>,
                code: ({ children }) => (
                  <code className="bg-[#1a1a1a] text-[#00ff88] px-1 py-0.5 rounded font-mono text-xs">{children}</code>
                ),
                pre: ({ children }) => (
                  <pre className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg p-4 overflow-x-auto mb-4">{children}</pre>
                ),
                strong: ({ children }) => <strong className="text-[#00ff88] font-bold">{children}</strong>,
              }}
            >
              {selected.content}
            </ReactMarkdown>
          </div>
        ) : (
          <div className="flex items-center justify-center h-full text-[#888888]">
            Select a document from the list to view it.
          </div>
        )}
      </div>
    </div>
  )
}
