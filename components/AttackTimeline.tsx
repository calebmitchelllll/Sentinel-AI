'use client'

interface TimelineStep {
  time: string
  event: string
  significance: string
}

const ATTACK_KEYWORDS = ['attack', 'escalation', 'exfiltration', 'suspicious', 'attacker', 'unauthorized', 'compromise', 'privilege', 'malicious', 'stolen']

function isAttackEvent(significance: string): boolean {
  const lower = significance.toLowerCase()
  return ATTACK_KEYWORDS.some((kw) => lower.includes(kw))
}

export default function AttackTimeline({ timeline }: { timeline: TimelineStep[] }) {
  if (!timeline || timeline.length === 0) {
    return <p className="text-white/30 text-sm">No timeline data available.</p>
  }

  return (
    <div className="relative">
      {timeline.map((step, i) => {
        const isAttack = isAttackEvent(step.significance)
        const isLast = i === timeline.length - 1

        return (
          <div key={i} className="flex gap-4 relative">
            {/* Left: time */}
            <div className="w-36 shrink-0 pt-1">
              <span className="font-mono text-xs text-white/30">{step.time.replace('T', ' ').replace('Z', '')}</span>
            </div>

            {/* Center: dot + line */}
            <div className="flex flex-col items-center">
              <div
                className={`w-2.5 h-2.5 rounded-full border-2 mt-1.5 z-10 ${
                  isAttack
                    ? 'bg-red-500/80 border-red-400/80 shadow-[0_0_8px_rgba(239,68,68,0.4)]'
                    : 'bg-purple-500/80 border-purple-400/80 shadow-[0_0_8px_rgba(168,85,247,0.3)]'
                }`}
              />
              {!isLast && <div className="w-px flex-1 bg-white/[0.06] mt-1" />}
            </div>

            {/* Right: event + significance */}
            <div className="pb-6 flex-1">
              <p className={`font-semibold text-sm tracking-wide ${isAttack ? 'text-red-400' : 'text-purple-300'}`}>
                {step.event}
              </p>
              <p className="text-white/40 text-xs mt-0.5 leading-relaxed">{step.significance}</p>
            </div>
          </div>
        )
      })}
    </div>
  )
}
