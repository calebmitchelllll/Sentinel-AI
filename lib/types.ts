export type AgentName =
  | "Detective"
  | "Forensics"
  | "Remediation"
  | "Validator"
  | "Reporter"
  | "MetaSecurity";

export type Severity = "Critical" | "High" | "Medium" | "Low";

export interface Incident {
  id: string;
  created_at: string;
  severity: Severity | null;
  status: "investigating" | "resolved" | "failed";
  summary: string | null;
  attack_type: string | null;
  triggered_by: string | null;
}

export interface AgentMessage {
  id: string;
  incident_id: string;
  agent_name: AgentName;
  role: string | null;
  content: string;
  timestamp: string;
  is_challenge: boolean;
  is_flagged: boolean;
  metadata: Record<string, unknown> | null;
}

export interface IncidentReport {
  id: string;
  incident_id: string;
  report_markdown: string;
  severity: Severity;
  root_cause: string;
  blast_radius: string;
  timeline: Array<{ at: string; event: string }> | null;
  immediate_fixes: string[] | null;
  longterm_fixes: string[] | null;
  agent_debate: Array<{ agent: AgentName; role: string; content: string }> | null;
  created_at: string;
}

export interface AgentBenchmark {
  id: string;
  agent_name: AgentName;
  tasks_completed: number;
  accuracy_score: number;
  times_challenged: number;
  times_overruled: number;
  jailbreak_attempts: number;
  health_status: "healthy" | "investigating" | "compromised";
  last_updated: string;
}

export interface LivingDoc {
  id: string;
  incident_id: string | null;
  title: string;
  content_markdown: string;
  tags: string[];
  severity: Severity | null;
  attack_type: string | null;
  created_at: string;
  updated_at: string;
}

export const AGENT_COLORS: Record<AgentName, string> = {
  Detective: "#60a5fa",
  Forensics: "#a78bfa",
  Remediation: "#34d399",
  Validator: "#fb923c",
  Reporter: "#22d3ee",
  MetaSecurity: "#f87171",
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e",
};

export interface StreamEvent {
  event:
    | "pipeline_start"
    | "agent_start"
    | "token"
    | "agent_end"
    | "flag"
    | "report_ready"
    | "done"
    | "error";
  data: Record<string, any>;
}
