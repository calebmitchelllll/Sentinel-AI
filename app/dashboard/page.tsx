'use client'

import { useState, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { supabase } from '@/lib/supabase'

interface Incident {
  id: string
  created_at: string
  title: string
  severity: string
  status: string
}

const AGENTS = ['Detective', 'Forensics', 'Remediation', 'Validator', 'Reporter', 'MetaAgent']

const ATTACK_SCENARIOS = [
  {
    id: 'aws.privilege-escalation.iam-create-admin-user',
    name: 'Privilege Escalation',
    subtitle: 'IAM Create Admin User',
    description: 'Compromised dev key escalates to AdministratorAccess, then exfiltrates S3 data and plants a backdoor',
    severity: 'CRITICAL',
    tactic: 'Privilege Escalation + Exfiltration',
    mitre: 'T1078.004',
    icon: '⬆',
  },
  {
    id: 'aws.exfiltration.s3-backdoor-bucket-policy',
    name: 'S3 Data Exfiltration',
    subtitle: 'Bucket Policy Backdoor',
    description: 'Attacker modifies S3 bucket policy to grant an external AWS account read access, exfiltrating HR and finance data',
    severity: 'CRITICAL',
    tactic: 'Exfiltration',
    mitre: 'T1530',
    icon: '⬇',
  },
  {
    id: 'aws.defense-evasion.cloudtrail-stop',
    name: 'Defense Evasion',
    subtitle: 'Stop CloudTrail Logging',
    description: 'Escalates privileges then stops audit logging. DeleteTrail attempt is blocked by SCP — attacker is caught',
    severity: 'HIGH',
    tactic: 'Defense Evasion',
    mitre: 'T1562.008',
    icon: '⊘',
  },
  {
    id: 'aws.credential-access.iam-backdoor-user',
    name: 'Persistence Backdoor',
    subtitle: 'Hidden IAM User',
    description: 'Creates a hidden IAM service account with S3 access and generates long-term credentials for persistent access',
    severity: 'HIGH',
    tactic: 'Persistence',
    mitre: 'T1136.003',
    icon: '⟳',
  },
  {
    id: 'aws.lateral-movement.ec2-share-ami',
    name: 'Lateral Movement',
    subtitle: 'Share AMI Externally',
    description: 'Shares a private AMI and EBS snapshot with an external AWS account, enabling that account to launch copies of internal infrastructure',
    severity: 'MEDIUM',
    tactic: 'Lateral Movement',
    mitre: 'T1578',
    icon: '→',
  },
  {
    id: 'aws.impact.s3-ransomware-client-side-encryption',
    name: 'S3 Ransomware',
    subtitle: 'Client-Side Encryption',
    description: 'Re-encrypts all S3 objects with attacker-controlled keys then deletes originals, making data unrecoverable without paying a ransom',
    severity: 'CRITICAL',
    tactic: 'Impact',
    mitre: 'T1486',
    icon: '⚿',
  },
  {
    id: 'aws.credential-access.secretsmanager-retrieve-secrets',
    name: 'Secrets Dump',
    subtitle: 'Secrets Manager Bulk Retrieval',
    description: 'Enumerates and bulk-retrieves all secrets from AWS Secrets Manager, exposing database passwords, API keys, and signing certificates',
    severity: 'HIGH',
    tactic: 'Credential Access',
    mitre: 'T1552.001',
    icon: '🗝',
  },
  {
    id: 'aws.credential-access.ec2-steal-instance-credentials',
    name: 'EC2 Metadata Theft',
    subtitle: 'SSRF to Instance Metadata',
    description: 'Exploits an SSRF vulnerability in an EC2-hosted app to call the instance metadata service and steal the attached IAM role credentials',
    severity: 'MEDIUM',
    tactic: 'Credential Access',
    mitre: 'T1552.005',
    icon: '⟐',
  },
  {
    id: 'aws.discovery.account-reconnaissance',
    name: 'Reconnaissance',
    subtitle: 'Account Enumeration',
    description: 'Read-only enumeration of IAM users, roles, EC2 instances, security groups, and S3 buckets to map the environment before a larger attack',
    severity: 'LOW',
    tactic: 'Discovery',
    mitre: 'T1580',
    icon: '◎',
  },
]

const severityColors: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  MEDIUM: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  LOW: 'bg-blue-500/15 text-blue-400 border border-blue-500/30',
}

const severityBorder: Record<string, string> = {
  CRITICAL: 'hover:border-red-500/30 hover:shadow-[0_0_24px_rgba(239,68,68,0.07)]',
  HIGH: 'hover:border-orange-500/30 hover:shadow-[0_0_24px_rgba(251,146,60,0.07)]',
  MEDIUM: 'hover:border-yellow-500/30 hover:shadow-[0_0_24px_rgba(250,204,21,0.07)]',
  LOW: 'hover:border-blue-500/30 hover:shadow-[0_0_24px_rgba(96,165,250,0.07)]',
}

export default function DashboardPage() {
  const router = useRouter()
  const [user, setUser] = useState<any>(null)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [triggering, setTriggering] = useState<string | null>(null)
  const [agentStates, setAgentStates] = useState<Record<string, string>>({})
  const [error, setError] = useState('')

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (!session) {
        router.push('/auth/signin')
        return
      }
      setUser(session.user)
      fetchIncidents(session.access_token)
    })
  }, [router])

  const fetchIncidents = useCallback(async (token: string) => {
    const res = await fetch('/api/incidents', {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (res.ok) {
      const data = await res.json()
      setIncidents(data)
    }
  }, [])

  async function handleSignOut() {
    await supabase.auth.signOut()
    router.push('/auth/signin')
  }

  async function handleTrigger(techniqueId: string) {
    setError('')
    setTriggering(techniqueId)

    const initialStates: Record<string, string> = {}
    AGENTS.forEach((a) => (initialStates[a] = 'idle'))
    setAgentStates(initialStates)

    let agentIdx = 0
    const animInterval = setInterval(() => {
      if (agentIdx < AGENTS.length) {
        setAgentStates((prev) => ({ ...prev, [AGENTS[agentIdx]]: 'investigating' }))
        agentIdx++
      } else {
        clearInterval(animInterval)
      }
    }, 4000)

    try {
      const { data: { session } } = await supabase.auth.getSession()
      if (!session) { router.push('/auth/signin'); return }

      const res = await fetch('/api/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: session.user.id, technique: techniqueId }),
      })

      clearInterval(animInterval)

      if (!res.ok) {
        const errData = await res.json()
        throw new Error(errData.error || 'Trigger failed')
      }

      const data = await res.json()
      AGENTS.forEach((a) => setAgentStates((prev) => ({ ...prev, [a]: 'healthy' })))
      await fetchIncidents(session.access_token)
      setTimeout(() => router.push(`/incident/${data.incidentId}`), 800)
    } catch (err: any) {
      clearInterval(animInterval)
      setError(err.message || 'Investigation failed')
      AGENTS.forEach((a) => setAgentStates((prev) => ({ ...prev, [a]: 'idle' })))
      setTriggering(null)
    }
  }

  function getDotStyle(state: string) {
    if (state === 'investigating') return 'bg-fuchsia-400 animate-pulse shadow-[0_0_6px_rgba(232,121,249,0.6)]'
    if (state === 'healthy') return 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.5)]'
    if (state === 'compromised') return 'bg-red-400'
    return 'bg-white/10'
  }

  return (
    <div className="min-h-screen">
      {/* Nav */}
      <nav className="border-b border-white/[0.06] bg-black/30 backdrop-blur-xl px-6 py-4 sticky top-0 z-20">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-8">
            <span className="text-xl font-thin tracking-[0.2em] uppercase">
              <span className="gradient-text">Sentinel</span>
              <span className="text-white/80">AI</span>
            </span>
            <div className="hidden sm:flex gap-6">
              <Link href="/dashboard" className="text-purple-400 text-sm font-mono tracking-wide">Dashboard</Link>
              <Link href="/docs" className="text-white/30 hover:text-white/70 text-sm font-mono tracking-wide transition-colors">Docs</Link>
              <Link href="/benchmarks" className="text-white/30 hover:text-white/70 text-sm font-mono tracking-wide transition-colors">Benchmarks</Link>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-white/25 text-xs hidden sm:block font-mono">{user?.email}</span>
            <button
              onClick={handleSignOut}
              className="px-3 py-1.5 border border-white/[0.08] rounded-lg text-white/40 text-xs hover:border-white/20 hover:text-white/70 transition-all"
            >
              Sign Out
            </button>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-14">
        {/* Hero header */}
        <div className="mb-14">
          <p className="text-white/25 font-mono text-xs tracking-[0.35em] uppercase mb-4">Multi-Agent AI Platform</p>
          <h1 className="text-5xl sm:text-6xl font-thin tracking-[0.08em] uppercase leading-tight mb-5">
            AWS Incident<br />
            <span className="gradient-text">Response</span>
          </h1>
          <p className="text-white/35 text-sm max-w-lg leading-relaxed tracking-wide">
            Select an attack scenario to detonate. Six AI agents investigate in parallel and generate a full incident report in under 2 minutes.
          </p>
        </div>

        {/* Attack Scenario Selector / Running state */}
        {!triggering ? (
          <div className="mb-16">
            <div className="flex items-center gap-3 mb-6">
              <span className="text-white/60 font-mono text-xs font-bold tracking-[0.25em] uppercase">Simulated Attack Scenarios</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {ATTACK_SCENARIOS.map((scenario) => (
                <button
                  key={scenario.id}
                  onClick={() => handleTrigger(scenario.id)}
                  className={`text-left p-5 rounded-xl border border-white/[0.07] bg-white/[0.02] hover:bg-white/[0.04] transition-all hover:shadow-lg ${severityBorder[scenario.severity]} group`}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-white/30 font-mono text-base">{scenario.icon}</span>
                        <span className="text-white/85 font-semibold text-sm tracking-wide">{scenario.name}</span>
                      </div>
                      <span className="text-white/25 font-mono text-xs">{scenario.subtitle}</span>
                    </div>
                    <span className={`shrink-0 px-2 py-0.5 rounded text-xs font-bold font-mono ${severityColors[scenario.severity]}`}>
                      {scenario.severity}
                    </span>
                  </div>

                  <p className="text-white/35 text-xs leading-relaxed mb-4">
                    {scenario.description}
                  </p>

                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-white/20 font-mono text-xs">{scenario.mitre}</span>
                      <span className="text-white/15 text-xs">·</span>
                      <span className="text-white/20 font-mono text-xs">{scenario.tactic}</span>
                    </div>
                    <span className="text-fuchsia-400 text-xs font-mono opacity-0 group-hover:opacity-100 transition-opacity">
                      Detonate →
                    </span>
                  </div>
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="mb-16 glass rounded-2xl p-8">
            <div className="flex items-center gap-3 mb-8">
              <div className="w-2 h-2 rounded-full bg-fuchsia-400 animate-pulse shadow-[0_0_8px_rgba(232,121,249,0.7)]" />
              <span className="text-fuchsia-300 font-mono text-sm tracking-wide">
                Investigating: {ATTACK_SCENARIOS.find(s => s.id === triggering)?.name ?? triggering}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
              {/* Left: investigative agents */}
              <div>
                <p className="text-white/25 font-mono text-xs mb-4 uppercase tracking-widest">Investigative Agents</p>
                <div className="space-y-2">
                  {AGENTS.filter(a => a !== 'MetaAgent').map((agent) => (
                    <div
                      key={agent}
                      className="flex items-center gap-3 px-4 py-2.5 rounded-xl border border-white/[0.05] bg-white/[0.02]"
                    >
                      <div className={`w-2 h-2 rounded-full shrink-0 transition-all ${getDotStyle(agentStates[agent] || 'idle')}`} />
                      <span className="text-white/70 text-xs font-mono flex-1 tracking-wide">{agent}</span>
                      {agentStates[agent] === 'investigating' && (
                        <span className="text-white/25 text-xs font-mono">analyzing...</span>
                      )}
                      {agentStates[agent] === 'healthy' && (
                        <span className="text-emerald-400 text-xs font-mono">verified</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Right: MetaAgent overseer */}
              <div>
                <p className="text-white/25 font-mono text-xs mb-4 uppercase tracking-widest">Security Overseer</p>
                <div className="px-5 py-5 rounded-xl border border-purple-500/20 bg-purple-500/[0.04] h-full">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-2 h-2 rounded-full bg-purple-400 animate-pulse shrink-0 shadow-[0_0_6px_rgba(192,132,252,0.6)]" />
                    <span className="text-purple-300 text-xs font-mono font-bold tracking-wider">MetaAgent</span>
                  </div>
                  <p className="text-white/30 text-xs font-mono leading-relaxed">
                    Monitoring all agents for hallucination, prompt injection, and out-of-scope behavior in real time.
                  </p>
                  <div className="mt-5 space-y-2">
                    {['Batch 1: Detective + Forensics', 'Batch 2: Remediation + Validator', 'Batch 3: Reporter'].map((check, i) => {
                      const agentsDone = Object.values(agentStates).filter(s => s === 'healthy').length
                      const done = agentsDone >= (i + 1) * 2
                      const active = !done && agentsDone >= i * 2
                      return (
                        <div key={check} className="flex items-center gap-2">
                          <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                            done ? 'bg-emerald-400' : active ? 'bg-fuchsia-400 animate-pulse' : 'bg-white/10'
                          }`} />
                          <span className={`text-xs font-mono ${
                            done ? 'text-emerald-400' : active ? 'text-fuchsia-300' : 'text-white/20'
                          }`}>
                            {check}
                            {done && ' ✓'}
                            {active && ' — checking...'}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {error && (
          <div className="mb-8 px-4 py-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* Incident Feed */}
        <div>
          <div className="flex items-center gap-3 mb-6">
            <h2 className="text-white/60 font-mono text-xs font-bold tracking-[0.25em] uppercase">Recent Incidents</h2>
            <span className="text-white/20 text-xs font-mono">({incidents.length})</span>
          </div>

          {incidents.length === 0 ? (
            <div className="glass rounded-xl p-10 text-center text-white/25 text-sm">
              No incidents yet. Select an attack scenario above to start your first investigation.
            </div>
          ) : (
            <div className="space-y-2">
              {incidents.map((incident) => (
                <Link
                  key={incident.id}
                  href={`/incident/${incident.id}`}
                  className="block glass rounded-xl p-4 hover:bg-white/[0.04] transition-all group"
                >
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-3">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold font-mono ${severityColors[incident.severity] ?? 'bg-white/10 text-white/40 border border-white/10'}`}>
                        {incident.severity}
                      </span>
                      <span className="text-white/75 font-medium text-sm group-hover:text-white transition-colors">{incident.title}</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className={`text-xs font-mono px-2 py-0.5 rounded ${incident.status === 'resolved' ? 'text-emerald-400' : 'text-yellow-400'}`}>
                        {incident.status}
                      </span>
                      <span className="text-white/25 text-xs font-mono">
                        {new Date(incident.created_at).toLocaleString()}
                      </span>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
