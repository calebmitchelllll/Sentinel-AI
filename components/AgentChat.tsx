'use client'

interface Message {
  agent: string
  content: string
}

const agentStyles: Record<string, { border: string; bg: string; color: string; role: string }> = {
  Detective: { border: 'border-blue-500', bg: 'bg-blue-950/30', color: 'text-blue-400', role: 'Threat Detection' },
  Forensics: { border: 'border-purple-500', bg: 'bg-purple-950/30', color: 'text-purple-400', role: 'Forensic Analysis' },
  Remediation: { border: 'border-green-500', bg: 'bg-green-950/30', color: 'text-green-400', role: 'Remediation Planning' },
  Validator: { border: 'border-yellow-500', bg: 'bg-yellow-950/30', color: 'text-yellow-400', role: 'Finding Validation' },
  Reporter: { border: 'border-teal-500', bg: 'bg-teal-950/30', color: 'text-teal-400', role: 'Incident Reporting' },
  MetaAgent: { border: 'border-red-500', bg: 'bg-red-950/30', color: 'text-red-400', role: 'Meta Monitoring' },
}

export default function AgentChat({ conversation }: { conversation: Message[] }) {
  return (
    <div className="space-y-4">
      {conversation.map((msg, i) => {
        const style = agentStyles[msg.agent] || {
          border: 'border-gray-500',
          bg: 'bg-gray-950/30',
          color: 'text-gray-400',
          role: 'Agent',
        }
        return (
          <div
            key={i}
            className={`rounded-lg border-l-4 ${style.border} ${style.bg} p-4`}
          >
            <div className="flex items-center gap-3 mb-2">
              <span className={`font-bold text-sm ${style.color}`}>{msg.agent}</span>
              <span className="text-white/30 text-xs">{style.role}</span>
              <span className="ml-auto text-white/30 text-xs">Agent #{i + 1}</span>
            </div>
            <pre className="font-mono text-sm text-white whitespace-pre-wrap break-words leading-relaxed">
              {msg.content}
            </pre>
          </div>
        )
      })}
    </div>
  )
}
