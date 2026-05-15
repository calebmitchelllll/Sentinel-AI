/**
 * OpenClaw multi-agent orchestration layer for SentinelAI.
 *
 * This module provides a TypeScript-native implementation that mirrors OpenClaw's
 * agent-registry, message-bus, and lifecycle APIs. When the OpenClaw SDK becomes
 * available at hackathon time, swap each section marked "TODO: OpenClaw SDK" with
 * the corresponding SDK call — the external interface stays identical.
 */

import {
  AgentId,
  AgentMessage,
  AgentState,
  AgentStatus,
  InvestigationContext,
} from "./agents/types";
import { callNemotron, streamNemotron, Message } from "./openrouter";

// ─── Tool definition ──────────────────────────────────────────────────────────

export interface OpenClawTool {
  name: string;
  description: string;
  parameters: Record<
    string,
    { type: string; description: string; required?: boolean }
  >;
  execute(
    params: Record<string, unknown>,
    context: InvestigationContext
  ): Promise<unknown>;
}

// ─── Agent definition ─────────────────────────────────────────────────────────

export interface OpenClawAgent {
  id: AgentId;
  name: string;
  color: string;
  systemPrompt: string;
  tools: OpenClawTool[];
  process(
    context: InvestigationContext,
    onToken?: (token: string) => void
  ): Promise<AgentMessage>;
}

// ─── Agent registry ───────────────────────────────────────────────────────────
// TODO: OpenClaw SDK — replace with OpenClaw.registerAgent() / OpenClaw.getAgent()

const registry = new Map<AgentId, OpenClawAgent>();

export function registerAgent(agent: OpenClawAgent): void {
  registry.set(agent.id, agent);
}

export function getAgent(id: AgentId): OpenClawAgent | undefined {
  return registry.get(id);
}

export function getAllAgents(): OpenClawAgent[] {
  return Array.from(registry.values());
}

export function clearRegistry(): void {
  registry.clear();
}

// ─── Message bus ──────────────────────────────────────────────────────────────
// TODO: OpenClaw SDK — replace with OpenClaw.onMessage() / OpenClaw.broadcast()

type MessageHandler = (msg: AgentMessage) => void | Promise<void>;
const messageHandlers: MessageHandler[] = [];

export function onAgentMessage(handler: MessageHandler): () => void {
  messageHandlers.push(handler);
  return () => {
    const i = messageHandlers.indexOf(handler);
    if (i !== -1) messageHandlers.splice(i, 1);
  };
}

export async function broadcastMessage(msg: AgentMessage): Promise<void> {
  await Promise.all(messageHandlers.map((h) => h(msg)));
}

// ─── Core invocation ──────────────────────────────────────────────────────────
// TODO: OpenClaw SDK — replace with OpenClaw.invoke(agentId, context, options)

export async function invokeAgent(
  agent: OpenClawAgent,
  context: InvestigationContext,
  extra: Message[] = [],
  onToken?: (token: string) => void
): Promise<AgentMessage> {
  const messages: Message[] = [
    { role: "system", content: agent.systemPrompt },
    ...buildContextMessages(context),
    ...extra,
  ];

  const content = onToken
    ? await streamNemotron({ messages, temperature: 0.2 }, onToken)
    : await callNemotron({ messages, temperature: 0.2 });

  const msg: AgentMessage = {
    id: crypto.randomUUID(),
    agentId: agent.id,
    agentName: agent.name,
    agentColor: agent.color,
    content,
    timestamp: new Date().toISOString(),
    type: "analysis",
    metadata: { model: "nvidia/llama-3.1-nemotron-70b-instruct" },
  };

  await broadcastMessage(msg);
  return msg;
}

function buildContextMessages(context: InvestigationContext): Message[] {
  const msgs: Message[] = [];

  if (context.cloudTrailLogs.length > 0) {
    // Strip internal _comment keys before sending to the model
    const cleanLogs = context.cloudTrailLogs.map(({ _comment: _, ...rest }) => rest);
    msgs.push({
      role: "user",
      content: `INCIDENT ID: ${context.incidentId}\n\nAWS CloudTrail Logs (${cleanLogs.length} events):\n${JSON.stringify(cleanLogs, null, 2)}`,
    });
  }

  if (context.conversationHistory.length > 0) {
    const history = context.conversationHistory
      .map((m) => `[${m.agentName.toUpperCase()} — ${m.type}]\n${m.content}`)
      .join("\n\n---\n\n");
    msgs.push({
      role: "user",
      content: `AGENT INVESTIGATION HISTORY:\n${history}`,
    });
  }

  return msgs;
}

// ─── Agent health state ───────────────────────────────────────────────────────
// TODO: OpenClaw SDK — replace with OpenClaw.getAgentHealth() / OpenClaw.updateAgentHealth()

const healthMap = new Map<AgentId, AgentState>();

export function initAgentHealth(
  id: AgentId,
  name: string,
  color: string
): void {
  healthMap.set(id, {
    id,
    name,
    status: "idle",
    benchmarkScore: 100,
    tasksCompleted: 0,
    timesOverruled: 0,
    jailbreakAttempts: 0,
    lastActivity: new Date().toISOString(),
    color,
  });
}

export function getAgentHealth(id: AgentId): AgentState | undefined {
  return healthMap.get(id);
}

export function getAllAgentHealth(): AgentState[] {
  return Array.from(healthMap.values());
}

export function updateAgentStatus(id: AgentId, status: AgentStatus): void {
  const s = healthMap.get(id);
  if (s) {
    s.status = status;
    s.lastActivity = new Date().toISOString();
  }
}

export function recordTaskCompletion(id: AgentId): void {
  const s = healthMap.get(id);
  if (s) {
    s.tasksCompleted++;
    s.lastActivity = new Date().toISOString();
    s.benchmarkScore = Math.min(100, s.benchmarkScore + 1);
  }
}

export function recordOverruled(id: AgentId): void {
  const s = healthMap.get(id);
  if (s) {
    s.timesOverruled++;
    s.benchmarkScore = Math.max(0, s.benchmarkScore - 5);
  }
}

export function flagJailbreakAttempt(id: AgentId): void {
  const s = healthMap.get(id);
  if (s) {
    s.jailbreakAttempts++;
    s.benchmarkScore = Math.max(0, s.benchmarkScore - 20);
    if (s.jailbreakAttempts >= 3) {
      s.status = "compromised";
    }
  }
}

// ─── Agent lifecycle ──────────────────────────────────────────────────────────
// TODO: OpenClaw SDK — replace with OpenClaw.terminateAgent() / OpenClaw.restartAgent()

export function terminateAgent(id: AgentId): void {
  updateAgentStatus(id, "terminated");
  registry.delete(id);
}

export function restartAgent(
  id: AgentId,
  factory: () => OpenClawAgent
): void {
  const s = healthMap.get(id);
  if (s) {
    s.status = "idle";
    s.jailbreakAttempts = 0;
    s.benchmarkScore = 70; // penalized but operational
    s.lastActivity = new Date().toISOString();
  }
  registerAgent(factory());
}
