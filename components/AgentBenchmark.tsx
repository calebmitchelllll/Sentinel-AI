'use client'

interface Benchmark {
  id: string
  agent_name: string
  tasks_completed: number
  accuracy_score: number
  times_challenged: number
  times_overruled: number
  jailbreak_attempts_detected: number
  health_status: string
}

function AccuracyBadge({ score }: { score: number }) {
  const color = score >= 90 ? 'text-green-400' : score >= 70 ? 'text-yellow-400' : 'text-red-400'
  return <span className={`font-mono font-bold ${color}`}>{score}%</span>
}

function HealthBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    healthy: 'bg-green-500/20 text-green-400 border border-green-500',
    investigating: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500',
    compromised: 'bg-red-500/20 text-red-400 border border-red-500',
  }
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${styles[status] || styles.healthy}`}>
      {status}
    </span>
  )
}

export default function AgentBenchmark({ benchmarks }: { benchmarks: Benchmark[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#2a2a2a]">
            {['Agent', 'Tasks Completed', 'Accuracy Score', 'Challenged', 'Overruled', 'Jailbreak Attempts', 'Health'].map((h) => (
              <th key={h} className="text-left py-3 px-4 text-[#888888] font-mono text-xs uppercase tracking-widest">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {benchmarks.map((b) => (
            <tr key={b.id} className="border-b border-[#2a2a2a] hover:bg-[#1a1a1a] transition-colors">
              <td className="py-3 px-4 font-bold text-white">{b.agent_name}</td>
              <td className="py-3 px-4 font-mono text-[#00ff88]">{b.tasks_completed}</td>
              <td className="py-3 px-4"><AccuracyBadge score={Number(b.accuracy_score)} /></td>
              <td className="py-3 px-4 font-mono text-white">{b.times_challenged}</td>
              <td className="py-3 px-4 font-mono text-white">{b.times_overruled}</td>
              <td className="py-3 px-4 font-mono text-white">{b.jailbreak_attempts_detected}</td>
              <td className="py-3 px-4"><HealthBadge status={b.health_status} /></td>
            </tr>
          ))}
          {benchmarks.length === 0 && (
            <tr>
              <td colSpan={7} className="py-8 text-center text-[#888888]">No benchmark data yet. Trigger an incident to populate.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
