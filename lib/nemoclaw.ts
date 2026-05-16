/**
 * TypeScript client for the NemoClaw-sandboxed Python orchestrator.
 *
 * The orchestrator service runs inside the real NemoClaw sandbox (see
 * `services/nemoclaw.config.yaml`). This module is the thin TS contract
 * the Next.js API routes use to invoke it.
 */
import type { AgentName } from "./types";

export const NEMOCLAW_CONFIG = {
  model: process.env.NEMOTRON_MODEL || "nvidia/llama-3.1-nemotron-70b-instruct",
  serviceUrl: process.env.NEMOCLAW_SERVICE_URL || "http://localhost:8000",
  apiKeyEnv: "NVIDIA_API_KEY (or NEMOCLAW_API_KEY)",
} as const;

export type AgentDefinition = {
  name: AgentName;
  role: string;
  tools: readonly string[];
  color: string;
};

export async function nemoclawHealth(): Promise<{ status: string; model: string; has_api_key: boolean }> {
  const res = await fetch(`${NEMOCLAW_CONFIG.serviceUrl}/health`, { cache: "no-store" });
  if (!res.ok) throw new Error(`nemoclaw runner unhealthy (${res.status})`);
  return res.json();
}

export async function runAgentsStream(incidentId: string, logs: unknown[], meta?: unknown) {
  const res = await fetch(`${NEMOCLAW_CONFIG.serviceUrl}/run-agents`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
    body: JSON.stringify({ incidentId, logs, meta }),
  });
  if (!res.ok || !res.body) {
    throw new Error(`nemoclaw runner returned ${res.status}`);
  }
  return res.body;
}
