import type { AgentDefinition } from "../nemoclaw";

export const META: AgentDefinition = {
  name: "MetaSecurity",
  role: "Agent integrity monitor",
  tools: [
    "monitor_agent_behavior",
    "detect_prompt_injection",
    "benchmark_agent",
    "kill_agent",
    "restart_agent",
  ],
  color: "#f87171",
};
