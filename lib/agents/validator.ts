import type { AgentDefinition } from "../nemoclaw";

export const VALIDATOR: AgentDefinition = {
  name: "Validator",
  role: "Adversarial cross-check",
  tools: ["challenge_finding", "request_evidence", "confirm_or_reject"],
  color: "#fb923c",
};
