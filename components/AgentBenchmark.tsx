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
  const color = score >= 90 ? 'text-emerald-400' : score >= 70 ? 'text-yellow-400' : 'text-red-400'
  return <span className={`font-mono font-bold ${color}`}>{score}%</span>
}

function HealthBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    healthy: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/25',
    investigating: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/25',
    compromised: 'bg-red-500/15 text-red-400 border border-red-500/25',
  }
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-bold font-mono ${styles[status] || styles.healthy}`}>
      {status}
    </span>
  )
}

const CANONICAL_NAMES: Record<string, string> = {
  'metasecurity': 'MetaAgent',
  'meta security': 'MetaAgent',
  'meta-agent': 'MetaAgent',
  'metaagent': 'MetaAgent',
}

function canonicalize(name: string): string {
  return CANONICAL_NAMES[name.toLowerCase()] ?? name
}

function deduplicateByName(benchmarks: Benchmark[]): Benchmark[] {
  const seen = new Map<string, Benchmark>()
  for (const b of benchmarks) {
    const key = canonicalize(b.agent_name)
    const existing = seen.get(key)
    // Prefer higher accuracy score — old Python entries wrote 1% which is meaningless
    if (!existing || Number(b.accuracy_score) > Number(existing.accuracy_score)) {
      seen.set(key, { ...b, agent_name: key })
    }
  }
  return Array.from(seen.values())
}

export default function AgentBenchmark({ benchmarks }: { benchmarks: Benchmark[] }) {
  const deduped = deduplicateByName(benchmarks)
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-white/[0.06]">
            {['Agent', 'Tasks Completed', 'Accuracy Score', 'Challenged', 'Overruled', 'Jailbreak Attempts', 'Health'].map((h) => (
              <th key={h} className="text-left py-3.5 px-4 text-white/25 font-mono text-xs uppercase tracking-widest">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {deduped.map((b) => (
            <tr key={b.id} className="border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors">
              <td className="py-3.5 px-4 font-semibold text-white/80 font-mono">{b.agent_name}</td>
              <td className="py-3.5 px-4 font-mono text-purple-400">{b.tasks_completed}</td>
              <td className="py-3.5 px-4"><AccuracyBadge score={Number(b.accuracy_score)} /></td>
              <td className="py-3.5 px-4 font-mono text-white/60">{b.times_challenged}</td>
              <td className="py-3.5 px-4 font-mono text-white/60">{b.times_overruled}</td>
              <td className="py-3.5 px-4 font-mono text-white/60">{b.jailbreak_attempts_detected}</td>
              <td className="py-3.5 px-4"><HealthBadge status={b.health_status} /></td>
            </tr>
          ))}
          {benchmarks.length === 0 && (
            <tr>
              <td colSpan={7} className="py-10 text-center text-white/25 text-sm font-mono">
                No benchmark data yet. Trigger an incident to populate.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
