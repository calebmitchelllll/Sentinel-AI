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
    .from('living_docs')
    .select('id, created_at, incident_id, title, tags, severity, content_markdown')
    .order('created_at', { ascending: false })

  if (error) return NextResponse.json({ error: error.message }, { status: 500 })

  // Filter out internal sentinel-data records; map content_markdown → content
  const filtered = (data || [])
    .filter((doc: any) => !doc.tags?.includes('sentinel-data'))
    .map((doc: any) => ({
      ...doc,
      content: doc.content_markdown,
    }))

  return NextResponse.json(filtered)
}
