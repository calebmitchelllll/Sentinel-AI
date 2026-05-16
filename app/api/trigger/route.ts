import { NextRequest, NextResponse } from 'next/server'
import { supabaseAdmin, seedAgentBenchmarks } from '@/lib/supabaseAdmin'
import { runInvestigation } from '@/lib/orchestrator'
import { detonateAttack, randomTechnique, TECHNIQUES } from '@/lib/stratus'

export const maxDuration = 120

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}))
    const userId = (body.userId as string) || 'anonymous'
    const requestedTechnique = body.technique as string | undefined

    // Pick technique: explicit > random
    const techniqueId = requestedTechnique ?? randomTechnique()
    const techniqueInfo = TECHNIQUES.find((t) => t.id === techniqueId)

    const cloudtrailEvents = detonateAttack(techniqueId)

    await seedAgentBenchmarks()

    const { data: incident, error: createError } = await supabaseAdmin
      .from('incidents')
      .insert({
        summary: techniqueInfo
          ? `${techniqueInfo.name} — ${new Date().toISOString().slice(0, 10)}`
          : `AWS Attack Simulation — ${new Date().toISOString().slice(0, 10)}`,
        severity: techniqueInfo?.severity ?? 'CRITICAL',
        status: 'investigating',
        attack_type: techniqueId,
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
      technique: techniqueId,
      techniqueInfo,
      report,
      agentConversation: conversation,
      attackTimeline,
    })
  } catch (err: any) {
    console.error('[/api/trigger]', err)
    return NextResponse.json({ error: err.message || 'Internal server error' }, { status: 500 })
  }
}
