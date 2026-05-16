import type { AgentDefinition } from "../nemoclaw";

export const DETECTIVE: AgentDefinition = {
  name: "Detective",
  role: "Anomaly detection",
  tools: ["read_cloudtrail_logs", "flag_anomalies", "map_attack_path"],
  color: "#60a5fa",
};
