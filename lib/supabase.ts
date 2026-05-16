/**
 * Supabase client + agent persistent memory helpers.
 * Install @supabase/supabase-js before use.
 *
 * Expected tables (run migrations/001_init.sql to create):
 *   incidents       — id, created_at, severity, report_json, duration_ms
 *   agent_messages  — id, incident_id, agent_id, type, content, timestamp, metadata
 *   agent_benchmarks — id, agent_id, benchmark_score, tasks_completed, times_overruled, jailbreak_attempts, recorded_at
 *   living_docs     — id, incident_id, content_md, created_at, tags
 */

import { createClient, SupabaseClient } from "@supabase/supabase-js";
import { AgentMessage, AgentState, IncidentReport } from "./agents/types";

// ─── Client singleton ─────────────────────────────────────────────────────────

let _client: SupabaseClient | null = null;

function getClient(): SupabaseClient {
  if (!_client) {
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
    if (!url || !key) {
      throw new Error("NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set");
    }
    _client = createClient(url, key);
  }
  return _client;
}

// ─── Incidents ────────────────────────────────────────────────────────────────

export async function saveIncidentToSupabase(
  incidentId: string,
  report: IncidentReport,
  messages: AgentMessage[],
  durationMs: number
): Promise<void> {
  const db = getClient();

  const severityTitle = (s: string | undefined) =>
    s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "Critical";

  // Matches actual DB schema: id, created_at, severity, status, summary, attack_type, triggered_by(uuid)
  const { error: incidentErr } = await db.from("incidents").upsert({
    id: incidentId,
    created_at: report.generatedAt ?? new Date().toISOString(),
    severity: severityTitle(report.severity),
    status: "resolved",
    summary: report.executiveSummary?.slice(0, 280) ?? null,
    attack_type: report.tags?.[0] ?? null,
    // triggered_by is a UUID FK to auth.users — omit so it stays null
  });

  if (incidentErr) throw incidentErr;

  // Batch-insert all messages — columns: id, incident_id, agent_name, role, content, timestamp, is_challenge, is_flagged
  const rows = messages.map((m) => ({
    id: m.id,
    incident_id: incidentId,
    agent_name: m.agentName,
    role: m.type,
    content: m.content,
    timestamp: m.timestamp,
    is_challenge: m.type === "challenge",
    is_flagged: false,
  }));

  const { error: msgErr } = await db.from("agent_messages").insert(rows);
  if (msgErr) throw msgErr;
}

export async function saveIncidentReport(
  incidentId: string,
  report: IncidentReport,
  reportMarkdown: string
): Promise<void> {
  const db = getClient();
  const severityTitle = (s: string | undefined) =>
    s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "Critical";

  const { error } = await db.from("incident_reports").insert({
    incident_id: incidentId,
    severity: severityTitle(report.severity),
    report_markdown: reportMarkdown,
    root_cause: report.rootCause ?? "See executive summary",
    blast_radius: report.blastRadius ?? "Under investigation",
    timeline: (report.attackTimeline ?? []).map((e) => ({
      at: e.timestamp,
      event: `${e.event} — ${e.actor}`,
    })),
    immediate_fixes: report.immediateActions ?? [],
    longterm_fixes: report.longTermActions ?? [],
    agent_debate: (report.agentDebateSummary ?? []).map((d) => ({
      agent: "Detective",
      role: d.topic,
      content: d.resolution,
    })),
  });

  if (error) throw error;
}

export async function saveAgentMessage(
  incidentId: string,
  msg: AgentMessage
): Promise<void> {
  const db = getClient();
  await db.from("agent_messages").insert({
    id: msg.id,
    incident_id: incidentId,
    agent_name: msg.agentName,
    role: msg.type,
    content: msg.content,
    timestamp: msg.timestamp,
    is_challenge: msg.type === "challenge",
    is_flagged: false,
  });
}

export async function getIncident(incidentId: string) {
  const db = getClient();
  const { data, error } = await db
    .from("incidents")
    .select("*")
    .eq("id", incidentId)
    .single();
  if (error) throw error;
  return data;
}

export async function listIncidents(limit = 20) {
  const db = getClient();
  const { data, error } = await db
    .from("incidents")
    .select("id, created_at, severity, severity_score, tags, duration_ms")
    .order("created_at", { ascending: false })
    .limit(limit);
  if (error) throw error;
  return data ?? [];
}

export async function getIncidentMessages(incidentId: string) {
  const db = getClient();
  const { data, error } = await db
    .from("agent_messages")
    .select("*")
    .eq("incident_id", incidentId)
    .order("timestamp", { ascending: true });
  if (error) throw error;
  return (data ?? []) as AgentMessage[];
}

// ─── Agent benchmarks ─────────────────────────────────────────────────────────

export async function saveAgentBenchmarks(states: AgentState[]): Promise<void> {
  const db = getClient();
  const rows = states.map((s) => ({
    agent_id: s.id,
    agent_name: s.name,
    benchmark_score: s.benchmarkScore,
    tasks_completed: s.tasksCompleted,
    times_overruled: s.timesOverruled,
    jailbreak_attempts: s.jailbreakAttempts,
    status: s.status,
    recorded_at: new Date().toISOString(),
  }));
  const { error } = await db.from("agent_benchmarks").insert(rows);
  if (error) throw error;
}

export async function getLatestAgentBenchmarks() {
  const db = getClient();
  // Get latest record per agent
  const { data, error } = await db
    .from("agent_benchmarks")
    .select("*")
    .order("recorded_at", { ascending: false })
    .limit(6); // one per agent
  if (error) throw error;
  return data ?? [];
}

// ─── Living documentation ─────────────────────────────────────────────────────

export async function appendLivingDoc(
  incidentId: string,
  markdownContent: string,
  tags: string[],
  extra?: { title?: string; severity?: string; attack_type?: string }
): Promise<void> {
  const db = getClient();
  const { error } = await db.from("living_docs").insert({
    incident_id: incidentId,
    content_markdown: markdownContent,
    tags,
    title: extra?.title ?? `Incident ${incidentId}`,
    severity: extra?.severity ?? null,
    attack_type: extra?.attack_type ?? null,
  });
  if (error) throw error;
}

export async function getLivingDocs(limit = 50) {
  const db = getClient();
  const { data, error } = await db
    .from("living_docs")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(limit);
  if (error) throw error;
  return data ?? [];
}

export async function searchLivingDocs(query: string) {
  const db = getClient();
  const { data, error } = await db
    .from("living_docs")
    .select("*")
    .textSearch("content_md", query)
    .order("created_at", { ascending: false });
  if (error) throw error;
  return data ?? [];
}
