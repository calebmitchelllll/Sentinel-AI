import type { AgentDefinition } from "../nemoclaw";

export const FORENSICS: AgentDefinition = {
  name: "Forensics",
  role: "Root cause + blast radius",
  tools: ["analyze_iam_events", "trace_credential_usage", "assess_data_exposure"],
  color: "#a78bfa",
};
