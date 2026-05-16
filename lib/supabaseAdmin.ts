import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY!

export const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
})

// Actual column mapping for existing tables:
// incidents: id, created_at, severity, status, summary, attack_type, triggered_by
// agent_benchmarks: id, agent_name, tasks_completed, accuracy_score, times_challenged,
//                   times_overruled, jailbreak_attempts, health_status, last_updated
// living_docs: id, incident_id, title, content_markdown, tags, severity, attack_type,
//              search_tsv, created_at, updated_at

export async function seedAgentBenchmarks() {
  const { count } = await supabaseAdmin
    .from('agent_benchmarks')
    .select('*', { count: 'exact', head: true })

  if ((count ?? 0) === 0) {
    const agents = ['Detective', 'Forensics', 'Remediation', 'Validator', 'Reporter', 'MetaAgent']
    await supabaseAdmin.from('agent_benchmarks').insert(
      agents.map((name) => ({
        agent_name: name,
        tasks_completed: 0,
        accuracy_score: 100,
        times_challenged: 0,
        times_overruled: 0,
        jailbreak_attempts: 0,
        health_status: 'healthy',
      }))
    )
  }
}
