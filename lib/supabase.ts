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

  const { error: incidentErr } = await db.from("incidents").upsert({
    id: incidentId,
    severity: report.severity,
    severity_score: report.severityScore,
    report_json: report,
    duration_ms: durationMs,
    tags: report.tags,
    created_at: report.generatedAt,
  });

  if (incidentErr) throw incidentErr;

  // Batch-insert all messages
  const rows = messages.map((m) => ({
    id: m.id,
    incident_id: incidentId,
    agent_id: m.agentId,
    agent_name: m.agentName,
    agent_color: m.agentColor,
    type: m.type,
    content: m.content,
    target_agent_id: m.targetAgentId ?? null,
    severity: m.severity ?? null,
    metadata: m.metadata ?? null,
    timestamp: m.timestamp,
  }));

  const { error: msgErr } = await db.from("agent_messages").insert(rows);
  if (msgErr) throw msgErr;
}

export async function saveAgentMessage(
  incidentId: string,
  msg: AgentMessage
): Promise<void> {
  const db = getClient();
  await db.from("agent_messages").insert({
    id: msg.id,
    incident_id: incidentId,
    agent_id: msg.agentId,
    agent_name: msg.agentName,
    agent_color: msg.agentColor,
    type: msg.type,
    content: msg.content,
    target_agent_id: msg.targetAgentId ?? null,
    severity: msg.severity ?? null,
    metadata: msg.metadata ?? null,
    timestamp: msg.timestamp,
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
  tags: string[]
): Promise<void> {
  const db = getClient();
  const { error } = await db.from("living_docs").insert({
    incident_id: incidentId,
    content_md: markdownContent,
    tags,
    created_at: new Date().toISOString(),
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
