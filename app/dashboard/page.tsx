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
  CRITICAL: 'bg-red-500/20 text-red-400 border border-red-500/60',
  HIGH: 'bg-orange-500/20 text-orange-400 border border-orange-500/60',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/60',
  LOW: 'bg-blue-500/20 text-blue-400 border border-blue-500/60',
}

const severityGlow: Record<string, string> = {
  CRITICAL: 'hover:border-red-500/60 hover:shadow-red-500/10',
  HIGH: 'hover:border-orange-500/60 hover:shadow-orange-500/10',
  MEDIUM: 'hover:border-yellow-500/60 hover:shadow-yellow-500/10',
  LOW: 'hover:border-blue-500/60 hover:shadow-blue-500/10',
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
    if (state === 'investigating') return 'bg-yellow-400 animate-pulse'
    if (state === 'healthy') return 'bg-[#00ff88]'
    if (state === 'compromised') return 'bg-red-400'
    return 'bg-[#2a2a2a]'
  }

  return (
    <div className="min-h-screen bg-[#0a0a0a]">
      {/* Nav */}
      <nav className="border-b border-[#2a2a2a] bg-[#111111] px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-8">
            <span className="text-xl font-bold font-mono">
              <span className="text-[#00ff88]">Sentinel</span>
              <span className="text-white">AI</span>
            </span>
            <div className="hidden sm:flex gap-6">
              <Link href="/dashboard" className="text-[#00ff88] text-sm font-mono">Dashboard</Link>
              <Link href="/docs" className="text-[#888888] hover:text-white text-sm font-mono transition-colors">Docs</Link>
              <Link href="/benchmarks" className="text-[#888888] hover:text-white text-sm font-mono transition-colors">Benchmarks</Link>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-[#888888] text-xs hidden sm:block">{user?.email}</span>
            <button
              onClick={handleSignOut}
              className="px-3 py-1.5 border border-[#2a2a2a] rounded-lg text-[#888888] text-xs hover:border-[#444444] hover:text-white transition-colors"
            >
              Sign Out
            </button>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-10">
        {/* Header */}
        <div className="mb-10">
          <h1 className="text-3xl sm:text-4xl font-bold mb-4">
            AWS Incident Response<br />
            <span className="text-[#00ff88]">Powered by Autonomous AI Agents</span>
          </h1>
          <p className="text-[#888888] text-sm max-w-xl">
            Select an attack scenario to detonate. Six AI agents investigate in parallel and generate a full incident report in under 2 minutes.
          </p>
        </div>

        {/* Attack Scenario Selector / Running state */}
        {!triggering ? (
          <div className="mb-12">
            <div className="flex items-center gap-3 mb-4">
              <span className="text-white font-mono text-sm font-bold">SIMULATED ATTACK SCENARIOS</span>
              <span className="text-[#444] text-xs font-mono">— stratus-red-team techniques</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {ATTACK_SCENARIOS.map((scenario) => (
                <button
                  key={scenario.id}
                  onClick={() => handleTrigger(scenario.id)}
                  className={`text-left p-5 rounded-lg border border-[#2a2a2a] bg-[#111111] transition-all hover:shadow-lg ${severityGlow[scenario.severity]} group`}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[#888] font-mono text-lg">{scenario.icon}</span>
                        <span className="text-white font-bold text-sm">{scenario.name}</span>
                      </div>
                      <span className="text-[#555] font-mono text-xs">{scenario.subtitle}</span>
                    </div>
                    <span className={`shrink-0 px-2 py-0.5 rounded text-xs font-bold font-mono ${severityColors[scenario.severity]}`}>
                      {scenario.severity}
                    </span>
                  </div>

                  <p className="text-[#888888] text-xs leading-relaxed mb-4">
                    {scenario.description}
                  </p>

                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-[#444] font-mono text-xs">{scenario.mitre}</span>
                      <span className="text-[#333] text-xs">·</span>
                      <span className="text-[#444] font-mono text-xs">{scenario.tactic}</span>
                    </div>
                    <span className="text-[#00ff88] text-xs font-mono opacity-0 group-hover:opacity-100 transition-opacity">
                      Detonate →
                    </span>
                  </div>
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="mb-12 rounded-lg border border-[#2a2a2a] bg-[#111111] p-8">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-2 h-2 rounded-full bg-[#00ff88] animate-pulse" />
              <span className="text-[#00ff88] font-mono text-sm">
                Investigating: {ATTACK_SCENARIOS.find(s => s.id === triggering)?.name ?? triggering}
              </span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {AGENTS.map((agent) => (
                <div
                  key={agent}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg border border-[#2a2a2a] bg-[#0a0a0a]"
                >
                  <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${getDotStyle(agentStates[agent] || 'idle')}`} />
                  <span className="text-white text-xs font-mono">{agent}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {error && (
          <div className="mb-6 px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* Incident Feed */}
        <div>
          <h2 className="text-white font-bold text-lg mb-4 font-mono">
            Recent Incidents
            <span className="ml-3 text-[#888888] text-sm font-normal">({incidents.length})</span>
          </h2>

          {incidents.length === 0 ? (
            <div className="rounded-lg border border-[#2a2a2a] bg-[#111111] p-8 text-center text-[#888888] text-sm">
              No incidents yet. Select an attack scenario above to start your first investigation.
            </div>
          ) : (
            <div className="space-y-3">
              {incidents.map((incident) => (
                <Link
                  key={incident.id}
                  href={`/incident/${incident.id}`}
                  className="block rounded-lg border border-[#2a2a2a] bg-[#111111] p-4 hover:border-[#444444] transition-colors"
                >
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-3">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold font-mono ${severityColors[incident.severity] ?? 'bg-gray-500/20 text-gray-400 border border-gray-500'}`}>
                        {incident.severity}
                      </span>
                      <span className="text-white font-medium">{incident.title}</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className={`text-xs font-mono px-2 py-0.5 rounded ${incident.status === 'resolved' ? 'text-[#00ff88]' : 'text-yellow-400'}`}>
                        {incident.status}
                      </span>
                      <span className="text-[#888888] text-xs">
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
