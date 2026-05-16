import { NextRequest, NextResponse } from 'next/server'
import { supabaseAdmin, seedAgentBenchmarks } from '@/lib/supabaseAdmin'
import { runInvestigation } from '@/lib/orchestrator'
import path from 'path'
import fs from 'fs'

export const maxDuration = 120

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}))
    const userId = body.userId || 'anonymous'

    const dataPath = path.join(process.cwd(), 'data', 'cloudtrail-demo.json')
    const cloudtrailEvents = JSON.parse(fs.readFileSync(dataPath, 'utf-8'))

    // Seed benchmarks if needed
    await seedAgentBenchmarks()

    // Create incident using actual schema columns
    const { data: incident, error: createError } = await supabaseAdmin
      .from('incidents')
      .insert({
        summary: `AWS Credential Compromise — ${new Date().toISOString().slice(0, 10)}`,
        severity: 'CRITICAL',
        status: 'investigating',
        attack_type: 'credential-theft',
        triggered_by: userId,
      })
      .select()
      .single()

    if (createError || !incident) {
      return NextResponse.json({ error: 'Failed to create incident', details: createError }, { status: 500 })
    }

    const { report, conversation, attackTimeline } = await runInvestigation(incident.id, cloudtrailEvents)

    return NextResponse.json({
      incidentId: incident.id,
      status: 'complete',
      report,
      agentConversation: conversation,
      attackTimeline,
    })
  } catch (err: any) {
    console.error('[/api/trigger]', err)
    return NextResponse.json({ error: err.message || 'Internal server error' }, { status: 500 })
  }
}
