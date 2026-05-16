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
    return <p className="text-[#888888] text-sm">No timeline data available.</p>
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
              <span className="font-mono text-xs text-[#888888]">{step.time.replace('T', ' ').replace('Z', '')}</span>
            </div>

            {/* Center: dot + line */}
            <div className="flex flex-col items-center">
              <div
                className={`w-3 h-3 rounded-full border-2 mt-1 z-10 ${
                  isAttack ? 'bg-red-500 border-red-400' : 'bg-green-500 border-green-400'
                }`}
              />
              {!isLast && <div className="w-px flex-1 bg-[#2a2a2a] mt-1" />}
            </div>

            {/* Right: event + significance */}
            <div className="pb-6 flex-1">
              <p className={`font-bold text-sm ${isAttack ? 'text-red-400' : 'text-green-400'}`}>
                {step.event}
              </p>
              <p className="text-[#888888] text-xs mt-0.5 leading-relaxed">{step.significance}</p>
            </div>
          </div>
        )
      })}
    </div>
  )
}
