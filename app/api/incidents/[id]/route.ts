import { NextRequest, NextResponse } from 'next/server'
import { supabaseAdmin } from '@/lib/supabaseAdmin'
import { createClient } from '@supabase/supabase-js'

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const authHeader = req.headers.get('authorization')
  const token = authHeader?.replace('Bearer ', '')

  if (!token) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const userClient = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  )
  const { data: { user }, error: authError } = await userClient.auth.getUser(token)
  if (authError || !user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { data: incident, error } = await supabaseAdmin
    .from('incidents')
    .select('*')
    .eq('id', params.id)
    .single()

  if (error) return NextResponse.json({ error: error.message }, { status: 500 })

  // Fetch sentinel-data living_doc for this incident (holds report, conversation, timeline)
  const { data: sentinelDocs } = await supabaseAdmin
    .from('living_docs')
    .select('content_markdown')
    .eq('incident_id', params.id)
    .contains('tags', ['sentinel-data'])
    .limit(1)

  let report = {}
  let agent_conversation: any[] = []
  let attack_timeline: any[] = []
  let meta_assessments: any[] = []

  if (sentinelDocs && sentinelDocs.length > 0) {
    try {
      const parsed = JSON.parse(sentinelDocs[0].content_markdown)
      report = parsed.report || {}
      agent_conversation = parsed.agent_conversation || []
      attack_timeline = parsed.attack_timeline || []
      meta_assessments = parsed.meta_assessments || []
    } catch {
      // sentinel data malformed — keep defaults
    }
  }

  return NextResponse.json({
    ...incident,
    title: incident.summary,
    report,
    agent_conversation,
    attack_timeline,
    meta_assessments,
  })
}
