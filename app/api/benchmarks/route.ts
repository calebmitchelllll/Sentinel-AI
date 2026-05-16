import { NextRequest, NextResponse } from 'next/server'
import { supabaseAdmin } from '@/lib/supabaseAdmin'
import { createClient } from '@supabase/supabase-js'

export async function GET(req: NextRequest) {
  const authHeader = req.headers.get('authorization')
  const token = authHeader?.replace('Bearer ', '')

  if (!token) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const userClient = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  )
  const { data: { user }, error: authError } = await userClient.auth.getUser(token)
  if (authError || !user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { data, error } = await supabaseAdmin
    .from('agent_benchmarks')
    .select('*')
    .order('agent_name')

  if (error) return NextResponse.json({ error: error.message }, { status: 500 })

  // Map jailbreak_attempts → jailbreak_attempts_detected and last_updated → updated_at
  const mapped = (data || []).map((b: any) => ({
    ...b,
    jailbreak_attempts_detected: b.jailbreak_attempts ?? 0,
    updated_at: b.last_updated,
  }))

  return NextResponse.json(mapped)
}
