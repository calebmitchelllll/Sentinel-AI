import type { AgentDefinition } from "../nemoclaw";

export const REMEDIATION: AgentDefinition = {
  name: "Remediation",
  role: "Immediate + long-term fixes",
  tools: ["suggest_immediate_fix", "suggest_longterm_fix", "validate_remediation"],
  color: "#34d399",
};
